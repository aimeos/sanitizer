<?php

namespace Aimeos\Sanitizer\Tests;

use Aimeos\Sanitizer\LegacyBackend;
use Aimeos\Sanitizer\Limits;
use Aimeos\Sanitizer\NativeBackend;
use Aimeos\Sanitizer\Policy;
use Aimeos\Sanitizer\Sane;
use Aimeos\Sanitizer\Tree;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

class SecurityTest extends TestCase
{
    public static function backends() : array
    {
        $backends = ['legacy' => [LegacyBackend::class]];
        if( class_exists('Dom\\HTMLDocument') ) {
            $backends['native'] = [NativeBackend::class];
        }
        return $backends;
    }

    #[DataProvider('backends')]
    public function testInputCannotSelectTheParserEncoding( string $backend ) : void
    {
        foreach( [
            '<meta charset="iso-2022-jp">',
            '<meta http-equiv="Content-Type" content="text/html; charset=iso-2022-jp">',
            '<meta charset="windows-1252">',
            '<meta charset="utf-16">',
        ] as $meta ) {
            foreach( [false, true] as $strict ) {
                $input = $meta . "\x1b\$B" . 'a<svg/onload=confirm(11)>a' . "\x1b(B";
                $output = $backend::sanitize($input, [], $strict);
                $this->assertStringNotContainsString('<svg', $output);
                $this->assertSame('<p>Grüße € 中文</p>', trim($backend::sanitize($meta . '<p>Grüße € 中文</p>', [], $strict)));
            }
        }
    }

    public function testInvalidUtf8CannotHideParserWork() : void
    {
        $attributes = implode(' ', array_map(fn($i) => 'a' . $i, range(1, 20000)));
        foreach( ["\xff", "\x80", "\xc0\xaf", "\xe2\x82", "\xed\xa0\x80", "\xf4\x90\x80\x80"] as $invalid ) {
            foreach( [
                'text' . $invalid,
                '<p title="' . $invalid . '">ok</p>',
                '<' . $invalid . 'div ' . $attributes . '>ok</div>',
                str_repeat('<' . $invalid . 'div>', 1000) . 'deep',
            ] as $input ) {
                $this->assertTrue(Limits::exceeds($input), bin2hex($invalid));
                $this->assertSame('', Sane::html($input));
                $this->assertSame('', Sane::strict($input));
            }
        }
        $input = '<p title="' . "\u{FFFD}" . '">Grüße € 中文 😀</p>';
        $this->assertFalse(Limits::exceeds($input));
        $this->assertSame($input, Sane::html($input));
        $this->assertSame($input, Sane::strict($input));
        $this->assertFalse(Limits::exceeds(''));
    }

    #[DataProvider('backends')]
    public function testScriptExceptionsCannotEnableForeignScripts( string $backend ) : void
    {
        foreach( [true, ['/approved.js']] as $scripts ) {
            foreach( ['<svg>%s</svg>', '<svg><foreignObject>%s</foreignObject></svg>', '<math><mtext>%s</mtext></math>'] as $wrapper ) {
                foreach( ['', ' href="https://untrusted.invalid/a.js"', ' xlink:href="https://untrusted.invalid/a.js"'] as $href ) {
                    $input = sprintf($wrapper, '<script src="/approved.js"' . $href . '>confirm(22)</script>');
                    $output = $backend::sanitize($input, ['svg' => true, 'math' => true, 'script' => $scripts]);
                    $this->assertStringNotContainsString('<script', $output, $input);
                    $this->assertStringNotContainsString('confirm(22)', $output, $input);
                }
            }
            $this->assertStringContainsString('<script src="/approved.js"></script>', $backend::sanitize('<script src="/approved.js"></script>', ['script' => $scripts]));
        }
    }

    #[DataProvider('backends')]
    public function testWhitespaceTargetsReceiveOpenerProtection( string $backend ) : void
    {
        foreach( [false, true] as $strict ) {
            foreach( $strict ? ['a'] : ['a', 'area', 'form'] as $tag ) {
                foreach( ['_self ', ' _parent', "_top\t", '  ', '_SELF ', 'named'] as $target ) {
                    $input = '<' . $tag . ' target="' . $target . '"></' . $tag . '>';
                    $this->assertStringContainsString('rel="noopener noreferrer"', $backend::sanitize($input, ['form' => true], $strict), $input);
                }
                foreach( ['', '_self', '_PARENT', '_Top'] as $target ) {
                    $this->assertStringNotContainsString('noopener', $backend::sanitize('<' . $tag . ' target="' . $target . '"></' . $tag . '>', ['form' => true], $strict));
                }
            }
        }
    }

    #[DataProvider('backends')]
    public function testRelMergingPreservesWholeTokens( string $backend ) : void
    {
        foreach( [
            ['', 'noopener noreferrer'],
            ["\f\t \r\n\v", 'noopener noreferrer'],
            ['ugc nofollow', 'ugc nofollow noopener noreferrer'],
            ["\fugc\tnoopener\n\fnoreferrer\f", 'ugc noopener noreferrer'],
            ['noopener noreferrer', 'noopener noreferrer'],
            ['NOOPENER NOREFERRER', 'NOOPENER NOREFERRER noopener noreferrer'],
            ['not-noopener noreferrer-extra', 'not-noopener noreferrer-extra noopener noreferrer'],
            ['ugc ugc noopener', 'ugc ugc noopener noreferrer'],
        ] as [$rel, $expected] ) {
            $this->assertSame($expected, Policy::mergeRel($rel));
            $this->assertSame($expected, Policy::mergeRel($expected));
            $input = '<a target="_blank" rel="' . $rel . '">ok</a>';
            $want = '<a target="_blank" rel="' . $expected . '">ok</a>';
            foreach( [false, true] as $strict ) {
                $this->assertSame($want, $backend::sanitize($input, [], $strict));
                $this->assertSame($want, $strict ? Sane::strict($input) : Sane::html($input));
            }
        }
    }

    #[DataProvider('backends')]
    public function testIframeFeaturesPreserveDirectiveBoundaries( string $backend ) : void
    {
        foreach( [
            ['', ''],
            ['; ;', ''],
            ['camera; autoplay; fullscreen; microphone', 'autoplay; fullscreen'],
            [" autoplay 'self' https://media.example ; fullscreen * ", "autoplay 'self' https://media.example; fullscreen *"],
            ['camera https://media.example autoplay; microphone; fullscreen', 'fullscreen'],
            ['autoplay-extra; geolocation; fullscreen', 'fullscreen'],
            [';Autoplay;autoplay;fullscreen;', 'Autoplay; autoplay; fullscreen'],
            ["autoplay\t'self'; fullscreen\f*; camera", "autoplay\t'self'; fullscreen\f*"],
        ] as [$features, $expected] ) {
            $this->assertSame($expected, Policy::filterAllowFeatures($features));
            $this->assertSame($expected, Policy::filterAllowFeatures($expected));
            $input = '<iframe src="/approved" allow="' . $features . '"></iframe>';
            $want = '<iframe src="/approved"' . ($expected === '' ? '' : ' allow="' . $expected . '"')
                . ' sandbox="allow-scripts allow-popups"></iframe>';
            $this->assertSame($want, $backend::sanitize($input, ['iframe' => ['/approved']]));
            $this->assertSame($want, Sane::html($input, ['iframe' => ['/approved']]));
        }
    }

    #[RunInSeparateProcess]
    #[DataProvider('backends')]
    public function testLargeRelFitsMemoryLimit( string $backend ) : void
    {
        ini_set('memory_limit', '64M');
        $rel = str_repeat('x ', 2000000);
        $input = '<a target="_blank" rel="' . $rel . '">ok</a>';
        $expected = '<a target="_blank" rel="' . $rel . 'noopener noreferrer">ok</a>';
        unset($rel);
        $this->assertFalse(Limits::exceeds($input));
        foreach( [false, true] as $strict ) {
            $this->assertSame($expected, $backend::sanitize($input, [], $strict));
            $this->assertSame($expected, $strict ? Sane::strict($input) : Sane::html($input));
        }
        $this->assertLessThan(64 * 1024 * 1024, memory_get_peak_usage(true));
    }

    #[RunInSeparateProcess]
    #[DataProvider('backends')]
    public function testLargeIframePermissionListsFitMemoryLimit( string $backend ) : void
    {
        ini_set('memory_limit', '64M');
        foreach( ['autoplay ' . str_repeat('x ', 1800000), str_repeat(';', 3000000)] as $features ) {
            $input = '<iframe src="/approved" allow="' . $features . '; camera; fullscreen; microphone"></iframe>';
            $kept = str_starts_with($features, 'autoplay') ? rtrim($features) . '; fullscreen' : 'fullscreen';
            $expected = '<iframe src="/approved" allow="' . $kept . '" sandbox="allow-scripts allow-popups"></iframe>';
            $this->assertFalse(Limits::exceeds($input));
            $this->assertSame($expected, $backend::sanitize($input, ['iframe' => ['/approved']]));
            $this->assertSame($expected, Sane::html($input, ['iframe' => ['/approved']]));
        }
        $this->assertLessThan(64 * 1024 * 1024, memory_get_peak_usage(true));
    }

    #[DataProvider('backends')]
    public function testIpv6UrlsSurviveSerialization( string $backend ) : void
    {
        foreach( ['https://[::1]/safe', 'http://[2001:db8::1]:8080/image.png', '//[::1]/safe'] as $url ) {
            foreach( [false, true] as $strict ) {
                $this->assertSame('<a href="' . $url . '">ok</a><img src="' . $url . '">', $backend::sanitize('<a href="' . $url . '">ok</a><img src="' . $url . '">', [], $strict));
            }
            $this->assertStringContainsString('src="' . $url . '"', $backend::sanitize('<script src="' . $url . '"></script>', ['script' => [$url]]));
        }
    }

    #[DataProvider('backends')]
    public function testSerializationPreservesAttributeAndTextBoundaries( string $backend ) : void
    {
        $input = '<body title="wrapper"><p title="&quot;&lt;img src=x onerror=confirm(1)&gt;&amp;">'
            . '&lt;script&gt; &amp;lt;img&amp;gt; Grüße</p>'
            . '<a href="https://[::1]/safe?a=1&amp;b=2" title="&amp;quot;">ok</a></body>';
        foreach( [false, true] as $strict ) {
            $output = $backend::sanitize($input, [], $strict);
            $this->assertStringNotContainsString('<body', $output);
            $this->assertStringNotContainsString('<script', $output);
            $this->assertSame($output, $backend::sanitize($output, [], $strict));
            $doc = (new \Masterminds\HTML5())->loadHTML($output);
            $p = $doc->getElementsByTagName('p')->item(0);
            $this->assertSame('"<img src=x onerror=confirm(1)>&', $p->getAttribute('title'));
            $this->assertSame('<script> &lt;img&gt; Grüße', $p->textContent);
            $this->assertSame('https://[::1]/safe?a=1&b=2', $doc->getElementsByTagName('a')->item(0)->getAttribute('href'));
        }
    }

    public function testDeclarationsCannotHideParserWork() : void
    {
        $attributes = '<div ';
        for( $i = 0; $i < 20000; $i++ ) {
            $attributes .= 'a' . $i . '=""';
        }
        $attributes .= '>ok</div>';
        foreach( ['<![CDATA[<!--]]>', '<!DOCTYPE html "<!--">', '<!bogus <!-->', '<?x <!--?>'] as $prefix ) {
            $input = $prefix . $attributes;
            $this->assertTrue(Limits::exceeds($input));
            $this->assertSame('', Sane::html($input));
            $this->assertSame('', Sane::strict($input));
        }
        foreach( ['<div><![CDATA[</div>]]>', '<div><!DOCTYPE html PUBLIC "></div>">', '<div><?x ></div>?>'] as $hiddenClose ) {
            $this->assertTrue(Limits::exceeds(str_repeat($hiddenClose, 1000)));
        }
        foreach( ['<!DOCTYPE html>', '<!DOCTYPE html PUBLIC "public" "system">', '<![CDATA[plain text]]>', '<?x plain text?>', '<!bogus>'] as $safe ) {
            $this->assertFalse(Limits::exceeds($safe . '<p>ok</p>'));
            $this->assertStringContainsString('<p>ok</p>', Sane::html($safe . '<p>ok</p>'));
        }
    }

    #[DataProvider('backends')]
    public function testUrlPrefixesRejectAmbiguousOriginsAndPaths( string $backend ) : void
    {
        $cases = [
            ['/\\untrusted.invalid/payload.js', '/'],
            ["/\t/untrusted.invalid/payload.js", '/'],
            ['/&#10;/untrusted.invalid/payload.js', '/'],
            ['//untrusted.invalid/payload.js', '/'],
            ['https://trusted.example@untrusted.invalid/a.js', 'https://trusted.example'],
            ['https://trusted.example.evil/a.js', 'https://trusted.example'],
            ['https://trusted.example:444/a.js', 'https://trusted.example'],
            ['https://trusted.example/safe/../uploads/a.js', 'https://trusted.example/safe/'],
            ['https://trusted.example/safe/%2E%2e/uploads/a.js', 'https://trusted.example/safe/'],
            ['https://trusted.example/safe/.%2e/uploads/a.js', 'https://trusted.example/safe/'],
            ['https://trusted.example/SAFE/a.js', 'https://trusted.example/safe/'],
            ['/Safe/a.js', '/safe/'],
            ['https://trusted.example/a.js?Token=value', 'https://trusted.example/a.js?token=value'],
            ['https://trusted.example/a.js', ''],
        ];
        foreach( ['script' => 'src', 'iframe' => 'src', 'object' => 'data', 'base' => 'href'] as $tag => $attribute ) {
            foreach( $cases as [$url, $prefix] ) {
                $output = $backend::sanitize('<' . $tag . ' ' . $attribute . '="' . $url . '"></' . $tag . '><p>ok</p>', [$tag => [$prefix]]);
                $this->assertStringNotContainsString('<' . $tag, $output, $backend . ' ' . $url);
                $this->assertStringContainsString('<p>ok</p>', $output);
            }
        }
    }

    #[DataProvider('backends')]
    public function testUrlPrefixesPreserveSafeUrls( string $backend ) : void
    {
        foreach( [
            ['HTTPS://TRUSTED.EXAMPLE/safe/a.js', 'https://trusted.example/safe/'],
            ['https://trusted.example:443/safe/a.js', 'https://trusted.example/safe/'],
            ['http://trusted.example:80/a.js', 'http://trusted.example'],
            ['https://trusted.example:8443/a.js', 'https://trusted.example:8443'],
            ['//trusted.example/safe/a.js', '//trusted.example/safe/'],
            ['/safe/a.js?version=A#part', '/safe/'],
            ['assets/a.js', 'assets/'],
            ['https://trusted.example/safe/a.js?next=../elsewhere', 'https://trusted.example/safe/'],
        ] as [$url, $prefix] ) {
            $output = $backend::sanitize('<script src="' . $url . '"></script>', ['script' => [$prefix]]);
            $this->assertStringContainsString('<script', $output, $url);
            $this->assertStringContainsString('src="' . $url . '"', $output);
        }
    }

    #[DataProvider('backends')]
    public function testStrictProfilePreservesRichText( string $backend ) : void
    {
        $input = '<h2 title="Heading">Grüße 中文</h2><p><strong>bold</strong> <em>italic</em></p>'
            . '<ul><li>item</li></ul><table><tbody><tr><th scope="col">H</th><td colspan="2">V</td></tr></tbody></table>'
            . '<img src="data:image/png;base64,AA==" alt="image"><a href="https://example.com" target="_blank">link</a>';
        $output = $backend::sanitize($input, [], true);
        foreach( ['Grüße 中文', '<strong>bold</strong>', '<li>item</li>', 'scope="col"', 'colspan="2"', 'data:image/png;', 'alt="image"', 'noopener noreferrer'] as $kept ) {
            $this->assertStringContainsString($kept, $output);
        }
    }

    #[DataProvider('backends')]
    public function testStrictProfileCannotEnableExecutableContent( string $backend ) : void
    {
        $input = '<script src="https://example.com/a.js"></script><style>body{display:none}</style>'
            . '<base href="/"><meta http-equiv="refresh" content="0;url=https://example.com">'
            . '<iframe src="https://example.com"></iframe><object data="https://example.com"></object>'
            . '<embed src="https://example.com"><svg><circle r="1"/></svg><template><p>hidden</p></template>'
            . '<app-widget><p>widget</p></app-widget><form><input name="field"></form><p>ok</p>';
        $allow = array_fill_keys(['script', 'style', 'base', 'meta', 'iframe', 'object', 'embed', 'svg', 'template', 'form'], true);
        $this->assertSame('<p>ok</p>', trim($backend::sanitize($input, $allow, true)));
    }

    #[DataProvider('backends')]
    public function testStrictProfileRemovesClobberingAndApplicationAttributes( string $backend ) : void
    {
        $input = '<a id="appConfig" name="url" href="/safe" class="widget" data-hint="&lt;img onerror=alert(1)&gt;"'
            . ' is="app-widget" x-init="alert(1)" v-html="payload" onclick="alert(1)" style="color:red" title="tip">ok</a>';
        $this->assertSame('<a href="/safe" title="tip">ok</a>', trim($backend::sanitize($input, [], true)));
        $this->assertStringContainsString('id="appConfig"', $backend::sanitize($input, []));
    }

    #[DataProvider('backends')]
    public function testStrictProfileRestrictsSchemesByContext( string $backend ) : void
    {
        foreach( ['intent:open', 'custom:action', 'data:image/png;base64,AA==', 'javascript:alert(1)'] as $uri ) {
            $this->assertSame('<a>ok</a>', trim($backend::sanitize('<a href="' . $uri . '">ok</a>', [], true)));
        }
        foreach( ['https://example.com', 'mailto:test@example.com', 'tel:+12345', '/local', '#fragment'] as $uri ) {
            $this->assertStringContainsString('href="' . $uri . '"', $backend::sanitize('<a href="' . $uri . '">ok</a>', [], true));
        }
        $this->assertSame('<img>', trim($backend::sanitize('<img src="mailto:test@example.com">', [], true)));
    }

    #[DataProvider('backends')]
    public function testCorpusRemainsSafeWhenReparsed( string $backend ) : void
    {
        foreach( require __DIR__ . '/fixtures/security.php' as $label => $input ) {
            foreach( [false, true] as $strict ) {
                $output = $backend::sanitize($input, [], $strict);
                $again = $backend::sanitize($output, [], $strict);
                $this->assertSame($output, $again, $backend . ' ' . $label);
                // Unmodified Masterminds misreads quoted form feeds, so it
                // cannot act as a browser reparse oracle. Older PHP checks the
                // round trip above; tests/browser.php checks actual browsers.
                if( !class_exists('Dom\\HTMLDocument') ) {
                    continue;
                }
                $document = \Dom\HTMLDocument::createFromString('<!doctype html><body>' . $output, LIBXML_NOERROR, 'UTF-8');
                foreach( $document->getElementsByTagName('*') as $element ) {
                    $tag = strtolower($element->localName);
                    $this->assertNotContains($tag, ['script', 'style', 'iframe', 'svg', 'math', 'template', 'noscript'], $label);
                    foreach( $element->attributes as $attr ) {
                        $this->assertFalse(str_starts_with(strtolower($attr->name), 'on'), $label);
                        if( in_array($attr->name, ['href', 'src'], true) ) {
                            $this->assertDoesNotMatchRegularExpression('/^[\x00-\x20]*(?:javascript|vbscript):/i', $attr->value, $label);
                        }
                    }
                }
            }
        }
    }

    public function testStrictEntryPointAppliesLimitsAndProfile() : void
    {
        $this->assertSame('<p>ok</p>', Sane::strict('<p id="appConfig">ok</p><app-widget>hidden</app-widget>'));
        $this->assertSame('', Sane::strict(str_repeat('<div>', 300)));
    }

    public function testAdjacentAttributesCannotBypassBudget() : void
    {
        foreach( ['"', "'"] as $quote ) {
            $input = '<div ';
            for( $i = 0; $i < 20000; $i++ ) {
                $input .= 'a' . $i . '=' . $quote . $quote;
            }
            $input .= '>ok</div>';
            $this->assertTrue(Limits::exceeds($input));
            $this->assertSame('', Sane::html($input));
            $this->assertTrue(Limits::exceeds('<script><!--</script>' . $input));
        }
        $this->assertStringContainsString('title="two"', Sane::html('<p lang="en"title="two">ok</p>'));
    }

    public function testControlCharactersCannotHideAttributeWork() : void
    {
        $flood = '<div ' . implode(' ', array_map(fn($i) => 'a' . $i, range(0, 4000))) . '>ok</div></div>';
        foreach( array_merge(range(0, 32), [127]) as $code ) {
            $control = chr($code);
            if( str_contains(" \t\r\n\f", $control) ) {
                continue;
            }
            foreach( ['"', "'"] as $quote ) {
                foreach( ['<div a=' . $control, '<div a=x' . $control, '<div a' . $control . '=' . $control] as $prefix ) {
                    $input = $prefix . $quote . '>' . $flood;
                    $this->assertTrue(Limits::exceeds($input), bin2hex($prefix . $quote));
                    if( $code === 11 ) {
                        $this->assertSame('', Sane::html($input));
                        $this->assertSame('', Sane::strict($input));
                    }
                }
            }
        }
        foreach( str_split(" \t\r\n\f") as $space ) {
            foreach( ['"', "'"] as $quote ) {
                $input = '<p title=' . $space . $quote . str_repeat('<div>', 300) . $quote . $space . 'lang=en>ok</p>';
                $this->assertFalse(Limits::exceeds($input));
                $this->assertStringContainsString('lang="en"', Sane::strict($input));
            }
        }
    }

    #[DataProvider('backends')]
    public function testPingChecksEveryUrl( string $backend ) : void
    {
        foreach( require __DIR__ . '/fixtures/ping.php' as $label => $case ) {
            $this->assertSame($case['blocked'], Policy::uriValueBlocked('ping', $case['value']), $label);
            $value = preg_replace_callback('/[\x00-\x1f]/', fn($m) => '&#' . ord($m[0]) . ';', htmlspecialchars($case['value'], ENT_QUOTES, 'UTF-8'));
            foreach( ['a', 'area'] as $tag ) {
                $input = '<' . $tag . ' href="/" ping="' . $value . '">' . ($tag === 'a' ? 'click</a>' : '');
                foreach( [$backend::sanitize($input, []), Sane::html($input)] as $output ) {
                    $doc = new \DOMDocument();
                    $doc->loadHTML('<?xml encoding="UTF-8">' . $output, LIBXML_NOERROR | LIBXML_NOWARNING);
                    $element = $doc->getElementsByTagName($tag)->item(0);
                    $this->assertNotNull($element, $label);
                    $this->assertSame(!$case['blocked'], $element->hasAttribute('ping'), $label);
                    if( !$case['blocked'] ) {
                        $this->assertSame($case['value'], $element->getAttribute('ping'), $label);
                    }
                }
                $this->assertStringNotContainsString('ping=', $backend::sanitize($input, [], true), $label);
                $this->assertStringNotContainsString('ping=', Sane::strict($input), $label);
            }
        }
    }

    #[DataProvider('backends')]
    public function testMetaRefreshChecksTheRedirectUrl( string $backend ) : void
    {
        foreach( require __DIR__ . '/fixtures/meta-refresh.php' as $label => $case ) {
            $this->assertSame($case['url'], Policy::metaRefreshUrl($case['content']), $label);
            $content = preg_replace_callback('/[\x00-\x1f]/', fn($m) => '&#' . ord($m[0]) . ';', htmlspecialchars($case['content'], ENT_QUOTES, 'UTF-8'));
            $input = '<meta http-equiv="ReFrEsH" content="' . $content . '">';
            foreach( [true, ['https://trusted.example/safe/']] as $allow ) {
                foreach( [$backend::sanitize($input, ['meta' => $allow]), Sane::html($input, ['meta' => $allow])] as $output ) {
                    if( $allow !== true && !$case['allowed'] ) {
                        $this->assertSame('', $output, $label);
                        continue;
                    }
                    $doc = new \DOMDocument();
                    $doc->loadHTML('<?xml encoding="UTF-8">' . $output, LIBXML_NOERROR | LIBXML_NOWARNING);
                    $element = $doc->getElementsByTagName('meta')->item(0);
                    $this->assertNotNull($element, $label);
                    $this->assertSame(!($case['blocked'] ?? false), $element->hasAttribute('content'), $label);
                    if( !($case['blocked'] ?? false) ) {
                        $this->assertSame($case['content'], $element->getAttribute('content'), $label);
                    }
                }
            }
            $this->assertSame('', Sane::html($input), $label);
            $this->assertSame('', $backend::sanitize($input, ['meta' => true], true), $label);
            $this->assertSame('', Sane::strict($input), $label);
        }
        // Ordinary metadata continues to compare its content directly.
        $input = '<meta property="og:image" content="https://trusted.example/safe/image.png">';
        $allow = ['meta' => ['https://trusted.example/safe/']];
        $this->assertSame($input, $backend::sanitize($input, $allow));
        $this->assertSame($input, Sane::html($input, $allow));
    }

    #[DataProvider('backends')]
    public function testSrcsetPreservesCandidateBoundaries( string $backend ) : void
    {
        foreach( require __DIR__ . '/fixtures/srcset.php' as $label => $case ) {
            $this->assertSame($case['blocked'], Policy::uriValueBlocked('srcset', $case['value']), $label);
            // Character references give both parsers the same decoded controls.
            $value = preg_replace_callback('/[\x00-\x1f]/', fn($m) => '&#' . ord($m[0]) . ';', htmlspecialchars($case['value'], ENT_QUOTES, 'UTF-8'));
            foreach( ['img', 'source'] as $tag ) {
                $input = '<' . $tag . ' srcset="' . $value . '">';
                $output = $backend::sanitize($input, []);
                if( $case['blocked'] ) {
                    $this->assertStringNotContainsString('srcset=', $output, $label);
                } else {
                    $doc = (new \Masterminds\HTML5())->loadHTML($output);
                    $this->assertSame($case['value'], $doc->getElementsByTagName($tag)->item(0)->getAttribute('srcset'), $label);
                }
                $this->assertStringNotContainsString('srcset=', $backend::sanitize($input, [], true), $label);
            }
            $input = '<img srcset="' . $value . '">';
            $this->assertSame(!$case['blocked'], str_contains(Sane::html($input), 'srcset='), $label);
            $this->assertSame('<img>', Sane::strict($input), $label);
        }
    }

    #[DataProvider('backends')]
    public function testQuotedFormFeedsRemainAttributeText( string $backend ) : void
    {
        $value = "\f><div " . implode(' ', array_map(fn($i) => 'a' . $i, range(0, 20000)))
            . '><img src=x onerror=confirm(55)></div>';
        foreach( ['"', "'"] as $quote ) {
            $input = '<p title=' . $quote . $value . $quote . ' onclick="bad()">ok</p><p>after</p>';
            $this->assertFalse(Limits::exceeds($input));
            foreach( [false, true] as $strict ) {
                $output = $backend::sanitize($input, [], $strict);
                $this->assertSame('<p title="' . $value . '">ok</p><p>after</p>', $output);
                $this->assertSame($output, $backend::sanitize($output, [], $strict));
                $this->assertSame($output, $strict ? Sane::strict($input) : Sane::html($input));
            }
            foreach( array_merge(range(0, 32), [127]) as $code ) {
                $input = '<p title=' . $quote . chr($code) . str_repeat('<div>', 300) . $quote . '>ok</p>';
                $this->assertFalse(Limits::exceeds($input), 'quoted control ' . $code);
            }
        }
        // Form feed remains valid whitespace outside a quoted value.
        $input = "<p\ftitle=\f\"tip\"\flang=en\fdir=ltr>ok</p>";
        $this->assertFalse(Limits::exceeds($input));
        $this->assertSame('<p title="tip" lang="en" dir="ltr">ok</p>', Sane::strict($input));
    }

    #[DataProvider('backends')]
    public function testQuotedControlsSurviveRepeatedSanitization( string $backend ) : void
    {
        foreach( [9, 10, 12] as $code ) {
            foreach( [chr($code), '&#' . $code . ';'] as $control ) {
                foreach( ['"', "'"] as $quote ) {
                    foreach( [
                        ['<p title=%sa%s&amp;b%s>ok</p>', '<p title="a' . chr($code) . '&amp;b">ok</p>', null],
                        ['<a href="/" rel=%sugc%snofollow%s>ok</a>', '<a href="/" rel="ugc' . chr($code) . 'nofollow">ok</a>', null],
                        ['<img srcset=%ssmall.jpg%s1x, large.jpg 2x%s>', '<img srcset="small.jpg' . chr($code) . '1x, large.jpg 2x">', '<img>'],
                    ] as [$template, $expected, $strictExpected] ) {
                        $input = sprintf($template, $quote, $control, $quote);
                        foreach( [false, true] as $strict ) {
                            $want = $strict ? ($strictExpected ?? $expected) : $expected;
                            $output = $backend::sanitize($input, [], $strict);
                            $this->assertSame($want, $output);
                            $this->assertSame($output, $backend::sanitize($output, [], $strict));
                            $this->assertSame($want, $strict ? Sane::strict($input) : Sane::html($input));
                            $this->assertSame($want, $strict ? Sane::strict($output) : Sane::html($output));
                        }
                    }
                }
            }
        }
    }

    #[RunInSeparateProcess]
    public function testLegacyScannerRejectsDiagnosticFloodWithinMemoryLimit() : void
    {
        ini_set('memory_limit', '64M');
        foreach( ["\0", "\x01", "\u{0080}", "\u{FDD0}", "\u{10FFFF}"] as $character ) {
            $input = str_repeat($character, intdiv(3000000, strlen($character)));
            $this->assertFalse(Limits::exceeds($input));
            foreach( [false, true] as $strict ) {
                $this->assertSame('', LegacyBackend::sanitize($input, [], $strict));
            }
            if( !class_exists('Dom\\HTMLDocument') ) {
                $this->assertSame('', Sane::html($input));
                $this->assertSame('', Sane::strict($input));
            }
        }
        $this->assertLessThan(64 * 1024 * 1024, memory_get_peak_usage(true));
    }

    public function testLegacyScannerSharesTheParserErrorBudget() : void
    {
        foreach( ["\0", "\x01", "\x0b", "\x7f", "\u{0080}", "\u{009F}", "\u{FDD0}", "\u{FDEF}",
            "\u{FFFE}", "\u{FFFF}", "\u{1FFFE}", "\u{10FFFF}", "\xff\u{FDD0}"] as $character ) {
            $text = str_repeat($character, 2048);
            foreach( [false, true] as $strict ) {
                $output = LegacyBackend::sanitize('<p>' . $text . '</p>', [], $strict);
                $this->assertStringStartsWith('<p>', $output, bin2hex($character));
                $this->assertStringEndsWith('</p>', $output);
                $this->assertSame('', LegacyBackend::sanitize($text . $character, [], $strict));
                // Scanner diagnostics leave no budget for tokenizer or tree errors.
                $this->assertSame('', LegacyBackend::sanitize($text . '&notanentity;', [], $strict));
                $this->assertSame('', LegacyBackend::sanitize($text . '</missing>', [], $strict));
                $this->assertSame($output, LegacyBackend::sanitize('<p>' . $text . '</p>', [], $strict));
            }
        }
        $text = str_repeat("\x01", 1024) . str_repeat('&notanentity;', 512) . str_repeat('</missing>', 512);
        $expected = str_repeat("\x01", 1024) . str_repeat('&amp;notanentity;', 512);
        $this->assertSame($expected, LegacyBackend::sanitize($text, []));
        $this->assertSame('', LegacyBackend::sanitize($text . '</missing>', []));

        $input = '<p title="' . str_repeat("\t\n\f", 3000) . '">Grüße € 中文 😀</p>';
        $this->assertSame($input, LegacyBackend::sanitize($input, []));
        $this->assertSame($input, LegacyBackend::sanitize($input, [], true));
    }

    public function testLegacyParserRejectsExcessiveErrors() : void
    {
        foreach( [
            str_repeat('&notanentity;', 20000),
            '<p title=' . str_repeat('`', 20000) . '>ok</p>',
            str_repeat('</missing>', 2049),
            str_repeat('&notanentity;', 1024) . str_repeat('</missing>', 1025),
        ] as $input ) {
            foreach( [false, true] as $strict ) {
                $this->assertSame('', LegacyBackend::sanitize('<p>before</p>' . $input . '<p>after</p>', [], $strict));
            }
            if( !class_exists('Dom\\HTMLDocument') ) {
                $this->assertSame('', Sane::html($input));
                $this->assertSame('', Sane::strict($input));
            }
        }
    }

    public function testLegacyParserErrorBudgetResetsBetweenDocuments() : void
    {
        $input = str_repeat('&notanentity;', 2048);
        $expected = str_repeat('&amp;notanentity;', 2048);
        foreach( [false, true] as $strict ) {
            $this->assertSame($expected, LegacyBackend::sanitize($input, [], $strict));
            $this->assertSame('', LegacyBackend::sanitize($input . '&notanentity;', [], $strict));
            $this->assertSame($expected . '<p>ok</p>', LegacyBackend::sanitize($input . '<p onclick="bad()">ok</p><script>bad()</script>', [], $strict));
        }
    }

    #[DataProvider('backends')]
    public function testManyValidCharacterReferencesStillWork( string $backend ) : void
    {
        $input = str_repeat('&amp;&lt;&gt;&quot;', 20000);
        $expected = str_repeat('&amp;&lt;&gt;"', 20000);
        foreach( [false, true] as $strict ) {
            $this->assertSame($expected, $backend::sanitize($input, [], $strict));
        }
        $this->assertSame($expected, Sane::html($input));
        $this->assertSame($expected, Sane::strict($input));
    }

    #[DataProvider('backends')]
    public function testFilteringContinuesAfterRemovedBranches( string $backend ) : void
    {
        $input = '<script>bad</script><p onclick="bad()">first'
            . '<object><b onclick="bad()">discarded</b></object>'
            . '<a href="javascript:bad()">link</a></p>'
            . '<div><script>bad</script></div><img onerror="bad()">'
            . '<object><p>last removed branch</p></object>';
        foreach( [false, true] as $strict ) {
            $this->assertSame('<p>first<a>link</a></p><div></div><img>', $backend::sanitize($input, [], $strict));
            // Filtering must not discard a branch before the full budget pass.
            $this->assertSame('', $backend::sanitize('<object>' . str_repeat('<div>', 300) . 'hidden', [], $strict));
        }
    }

    public function testTagNamesAndTextStatesCannotHideAttributes() : void
    {
        $attributes = '<div ';
        for( $i = 0; $i < 20000; $i++ ) {
            $attributes .= 'a' . $i . '=""';
        }
        $attributes .= '>ok</div>';
        foreach( [
            '<script:x>', '<script_x>', '<script.x>', '<script<x>', "<script\0x>",
            '<textarea:x>', '<title_x>', '<style.x>',
            '<style></stylex><!--</style>', '<style></style foo><!--</style>',
            '<style></style/><!--</style>', '<textarea></textareax><!--</textarea>',
            '<script><!--<script></script><!--</script>',
            '<math><desc><style>', '<svg><title><!--</title>',
            '<svg><foreignObject><style><!--</style>',
        ] as $prefix ) {
            $input = $prefix . $attributes;
            $this->assertTrue(Limits::exceeds($input), $prefix);
            $this->assertSame('', Sane::html($input), $prefix);
            $this->assertSame('', Sane::strict($input), $prefix);
        }
    }

    public function testDistinctTagNamesCannotCancelEachOthersDepth() : void
    {
        foreach( ['<div:a></div:b>', '<div_a></div_b>', '<div.a></div.b>'] as $unit ) {
            $input = str_repeat($unit, 1000);
            $this->assertTrue(Limits::exceeds($input), $unit);
            $this->assertSame('', Sane::html($input), $unit);
            $this->assertSame('', Sane::strict($input), $unit);
        }
        foreach( ['<div:a></div:a>', '<div_a></div_a>', '<custom-element></custom-element>'] as $unit ) {
            $this->assertFalse(Limits::exceeds(str_repeat($unit, 1000)), $unit);
        }
    }

    public function testUnambiguousTextAndForeignContentStillWork() : void
    {
        $this->assertSame('<textarea>&lt;div&gt;text&lt;/div&gt;</textarea>', Sane::html('<textarea><div>text</div></textarea>'));
        $this->assertSame('<p>ok</p>', Sane::html('<script><!-- comment --></script><p>ok</p>'));
        $this->assertStringContainsString('<title>tip</title>', Sane::html('<svg><title>tip</title><circle r="1"/></svg>', ['svg' => true]));
        $this->assertFalse(Limits::exceeds('<style></stylex>' . str_repeat('<div>', 1000) . '</style><p>ok</p>'));
        $this->assertStringContainsString('<p>ok</p>', Sane::html('<style></stylex>text</style><p>ok</p>'));
    }

    public function testCommentContentsCannotHideOrInventNesting() : void
    {
        foreach( ['-->', '--!>'] as $end ) {
            $this->assertTrue(Limits::exceeds(str_repeat('<div><!--</div>' . $end, 1000)));
            $this->assertSame('<p>ok</p>', Sane::html('<!--' . str_repeat('<div>', 1000) . $end . '<p>ok</p>'));
        }
        foreach( ['<!-->', '<!--->'] as $empty ) {
            $this->assertTrue(Limits::exceeds($empty . str_repeat('<div>', 1000)));
        }
        $this->assertSame('<p>ok</p>', Sane::html('<p>ok</p><!--' . str_repeat('<div>', 1000)));
        $this->assertTrue(Limits::exceeds('<style><!--</style>' . str_repeat('<div>', 1000)));
    }

    #[RunInSeparateProcess]
    public function testNonElementNodeFloodsAreRejectedBeforeParsing() : void
    {
        ini_set('memory_limit', '64M');
        foreach( ['<!-- x -->', '<!---->', '<!-->', '<!--->', '<!-- x --!>', '<!x>', '<?x?>', '<![CDATA[x]]>', '<!DOCTYPE html>', 'x<!-- x -->'] as $unit ) {
            $input = str_repeat($unit, 100000) . '<p>ok</p>';
            $this->assertTrue(Limits::exceeds($input), $unit);
            $this->assertSame('', Sane::html($input), $unit);
            $this->assertSame('', Sane::strict($input), $unit);
        }
        // Native template contents are invisible to the later DOM traversal.
        $input = '<template>' . str_repeat('<!-- x -->', 100000) . '</template><p>ok</p>';
        $this->assertTrue(Limits::exceeds($input));
        $this->assertSame('', Sane::html($input, ['template' => true]));
        $this->assertSame('', Sane::strict($input));
        $this->assertLessThan(64 * 1024 * 1024, memory_get_peak_usage(true));
    }

    public function testNodeBudgetIncludesTextBetweenComments() : void
    {
        $atLimit = str_repeat('<!-- x -->', 49998) . '<p>ok</p>';
        $this->assertFalse(Limits::exceeds($atLimit));
        $this->assertSame('<p>ok</p>', Sane::html($atLimit));
        $this->assertSame('<p>ok</p>', Sane::strict($atLimit));
        $this->assertTrue(Limits::exceeds('<!-- x -->' . $atLimit));
        $this->assertSame('', Sane::strict('<!-- x -->' . $atLimit));

        $input = str_repeat('x<!-- x -->', 24999) . '<p>ok</p>';
        $expected = str_repeat('x', 24999) . '<p>ok</p>';
        $this->assertFalse(Limits::exceeds($input));
        $this->assertSame($expected, Sane::html($input));
        $this->assertSame($expected, Sane::strict($input));
        $this->assertTrue(Limits::exceeds('x' . $atLimit));
        $this->assertTrue(Limits::exceeds($atLimit . 'x'));
        $this->assertTrue(Limits::exceeds('x<!-- x -->' . $input));
        // Elements still count even when mixed with otherwise cheap comments.
        $this->assertTrue(Limits::exceeds(str_repeat('<!-- x --><br>', 25001)));
    }

    public function testLiteralMarkupDoesNotConsumeTheNodeBudget() : void
    {
        $literal = str_repeat('<!-- x -->', 60000);
        foreach( ['<p title="' . $literal . '">ok</p>', '<textarea>' . $literal . '</textarea><p>ok</p>'] as $input ) {
            $this->assertFalse(Limits::exceeds($input));
            $this->assertStringEndsWith('ok</p>', Sane::html($input));
            $this->assertStringEndsWith('ok</p>', Sane::strict($input));
        }
        // Literal '<' and references within one text run do not create nodes.
        $input = str_repeat('a < 1 &amp; ', 1000);
        $this->assertFalse(Limits::exceeds($input));
        $this->assertSame(str_repeat('a &lt; 1 &amp; ', 1000), Sane::strict($input));
    }

    #[RunInSeparateProcess]
    public function testFormattingReconstructionIsBoundedBeforeParsing() : void
    {
        ini_set('memory_limit', '64M');
        foreach( ['a', 'b', 'big', 'code', 'em', 'font', 'i', 'nobr', 's', 'small', 'strike', 'strong', 'tt', 'u'] as $tag ) {
            $input = '';
            for( $i = 0; $i < 1000; $i++ ) {
                // Distinct attributes avoid the parser's duplicate-formatting cap.
                $input .= '<p><' . $tag . ' title="' . $i . '">text</p>';
            }
            $this->assertTrue(Limits::exceeds($input), $tag);
            $this->assertSame('', Sane::html($input), $tag);
            $this->assertSame('', Sane::strict($input), $tag);
        }
        // Even a fixed number of unclosed formatters can be copied many times;
        // implied paragraph closures must not erase that pending allocation cost.
        $input = '';
        for( $i = 0; $i < 50; $i++ ) {
            $input .= '<p><b title="' . $i . '">text';
        }
        $input .= str_repeat('<p>more</p>', 2000);
        $this->assertTrue(Limits::exceeds($input));
        $this->assertSame('', Sane::html($input));
        $this->assertSame('', Sane::strict($input));
        // A misnested formatting close also copies nodes during tree repair.
        $input = '';
        for( $i = 0; $i < 1000; $i++ ) {
            $input .= '<b title="' . $i . '"><div>text</b></div>';
        }
        $this->assertTrue(Limits::exceeds($input));
        $this->assertSame('', Sane::html($input));
        $this->assertSame('', Sane::strict($input));
        $this->assertLessThan(64 * 1024 * 1024, memory_get_peak_usage(true));
    }

    public function testFormattingCopiesIncludeAttributesAndTheirBytes() : void
    {
        $attributes = '';
        for( $i = 0; $i < 1000; $i++ ) {
            $attributes .= ' a' . $i;
        }
        foreach( [$attributes, ' title="' . str_repeat('x', 300000) . '"'] as $attrs ) {
            $input = '<p><b' . $attrs . '>text</p>' . str_repeat('<p>more</p>', 100);
            $this->assertTrue(Limits::exceeds($input));
            $this->assertSame('', Sane::html($input));
            $this->assertSame('', Sane::strict($input));
        }
    }

    public function testProperlyClosedFormattingDoesNotAccumulate() : void
    {
        $input = str_repeat('<p><b title="tip"><i>text</i></b></p>', 5000);
        $this->assertFalse(Limits::exceeds($input));
        $this->assertSame($input, Sane::html($input));
        $this->assertSame($input, Sane::strict($input));

        $literal = str_repeat('<p><b title="tip">text</p>', 1000);
        $this->assertFalse(Limits::exceeds('<!--' . $literal . '--><p>ok</p>'));
        $this->assertSame('<p>ok</p>', Sane::strict('<!--' . $literal . '--><p>ok</p>'));
        $this->assertFalse(Limits::exceeds('<textarea>' . $literal . '</textarea><p>ok</p>'));
        $this->assertSame('<p>ok</p>', Sane::strict('<textarea>' . $literal . '</textarea><p>ok</p>'));
    }

    #[RunInSeparateProcess]
    public function testTotalAttributeAllocationIsBoundedBeforeParsing() : void
    {
        ini_set('memory_limit', '64M');
        $tag = '<br';
        for( $i = 0; $i < 20; $i++ ) {
            $tag .= ' a' . $i;
        }
        $tag .= '>';
        $flood = str_repeat($tag, 40000) . '<p>ok</p>';
        $this->assertTrue(Limits::exceeds($flood));
        $this->assertSame('', Sane::html($flood));
        $this->assertSame('', Sane::strict($flood));

        $atLimit = str_repeat($tag, 5000) . '<p>ok</p>';
        $this->assertFalse(Limits::exceeds($atLimit));
        $this->assertSame(str_repeat('<br>', 5000) . '<p>ok</p>', Sane::strict($atLimit));
        $this->assertTrue(Limits::exceeds($atLimit . '<br extra>'));
        $this->assertSame('', Sane::html($atLimit . '<br extra>'));
        $this->assertSame('', Sane::strict($atLimit . '<br extra>'));
        $this->assertLessThan(64 * 1024 * 1024, memory_get_peak_usage(true));
    }

    #[DataProvider('backends')]
    public function testParsedBudgetIncludesTotalAttributes( string $backend ) : void
    {
        $doc = $backend === NativeBackend::class
            ? \Dom\HTMLDocument::createFromString('<!doctype html><html><body></body></html>', LIBXML_NOERROR, 'UTF-8')
            : (new \Masterminds\HTML5())->loadHTML('<!doctype html><html><body></body></html>');
        $body = $doc->getElementsByTagName('body')->item(0);
        for( $i = 0; $i < 5000; $i++ ) {
            $node = $body->appendChild($doc->createElement('br'));
            for( $j = 0; $j < 20; $j++ ) {
                $node->setAttribute('a' . $j, '');
            }
        }
        $this->assertTrue(Tree::prepare($doc));
        $body->setAttribute('extra', '');
        $this->assertFalse(Tree::prepare($doc));
    }

    #[DataProvider('backends')]
    public function testLiteralLessThanSurvivesWithoutRevivingMarkup( string $backend ) : void
    {
        foreach( [
            'price < 5' => 'price &lt; 5',
            'x <= 2' => 'x &lt;= 2',
            'trailing <' => 'trailing &lt;',
            '<3' => '&lt;3',
            '<é' => '&lt;é',
            '<<p>ok</p>' => '&lt;<p>ok</p>',
            '&amp;&amp;< 2' => '&amp;&amp;&lt; 2',
            '&lt;script&gt;alert(1)&lt;/script&gt;' => '&lt;script&gt;alert(1)&lt;/script&gt;',
            '<p>1 < 2<img src=x onerror=alert(1)></p>' => '<p>1 &lt; 2<img src="x"></p>',
            '&lt;<img src=x onerror=alert(1)>' => '&lt;<img src="x">',
        ] as $input => $expected ) {
            foreach( [false, true] as $strict ) {
                $output = $backend::sanitize($input, [], $strict);
                $this->assertSame($expected, $output, $input);
                $this->assertSame($expected, $backend::sanitize($output, [], $strict), $input);
            }
            $this->assertSame($expected, Sane::html($input), $input);
            $this->assertSame($expected, Sane::strict($input), $input);
        }
    }

    #[DataProvider('backends')]
    public function testParsedBudgetCountsNonElementNodes( string $backend ) : void
    {
        foreach( ['createComment', 'createTextNode'] as $factory ) {
            $doc = $backend === NativeBackend::class
                ? \Dom\HTMLDocument::createFromString('<!doctype html><html><body></body></html>', LIBXML_NOERROR, 'UTF-8')
                : (new \Masterminds\HTML5())->loadHTML('<!doctype html><html><body></body></html>');
            $body = $doc->getElementsByTagName('body')->item(0);
            for( $i = 0; $i < 50010; $i++ ) {
                $body->appendChild($doc->$factory('x'));
            }
            // Comments must count before removal; adjacent text nodes remain
            // distinct until the DOM is explicitly normalized.
            $this->assertFalse(Tree::prepare($doc), $factory);
        }
    }

    public function testParsedTreeIsCheckedWithoutRecursion() : void
    {
        $doc = new \DOMDocument();
        $node = $doc->appendChild($doc->createElement('html'));
        for( $i = 0; $i < 1000; $i++ ) {
            $node = $node->appendChild($doc->createElement('div'));
        }
        $this->assertFalse(Tree::prepare($doc));
        if( class_exists('Dom\\HTMLDocument') ) {
            $input = str_repeat('<p>hi</b> <i>there</p> <span>ok</div> ', 200);
            $this->assertTrue(Limits::exceeds($input));
            // Direct backend calls still check repaired DOMs independently.
            $this->assertSame('', NativeBackend::sanitize($input, []));
        }
    }
}
