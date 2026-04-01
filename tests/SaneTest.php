<?php

namespace Aimeos\Sanitizer\Tests;

use PHPUnit\Framework\TestCase;
use Aimeos\Sanitizer\Sane;


class SaneTest extends TestCase
{
    private static function sanitize( string $input, array $allow = [] ) : string
    {
        return trim( Sane::html( $input, $allow ) );
    }


    // ── Passthrough: safe HTML is untouched ──

    public function testPassthroughPlainText() : void
    {
        $this->assertSame( '<p>hello world</p>', self::sanitize( 'hello world' ) );
    }

    public function testPassthroughSafeElements() : void
    {
        $this->assertSame( '<p>text</p>', self::sanitize( '<p>text</p>' ) );
    }

    public function testPassthroughSafeAttributes() : void
    {
        $html = '<a href="https://example.com" class="link">click</a>';
        $this->assertSame( $html, self::sanitize( $html ) );
    }


    // ── 1. Unsafe element removal ──

    public function testRemovesScript() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><script>alert(1)</script>' ) );
    }

    public function testRemovesIframe() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><iframe src="https://evil.com"></iframe>' ) );
    }

    public function testRemovesStyle() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><style>body{display:none}</style>' ) );
    }

    public function testRemovesSvg() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><svg onload="alert(1)"></svg>' ) );
    }

    public function testRemovesObject() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><object data="https://evil.com/flash.swf"></object>' ) );
    }

    public function testRemovesEmbed() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><embed src="https://evil.com/flash.swf">' ) );
    }

    public function testRemovesBase() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<base href="https://evil.com"><p>ok</p>' ) );
    }

    public function testRemovesMeta() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<meta http-equiv="refresh" content="0;url=https://evil.com"><p>ok</p>' ) );
    }

    public function testRemovesLink() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<link rel="stylesheet" href="https://evil.com/style.css"><p>ok</p>' ) );
    }

    public function testRemovesMath() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><math><mi>x</mi></math>' ) );
    }

    public function testRemovesTemplate() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><template><img src=x onerror=alert(1)></template>' ) );
    }

    public function testRemovesNoscript() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<p>ok</p><noscript><img src=x></noscript>' ) );
    }


    // ── 2. HTML comment removal ──

    public function testRemovesComments() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<!-- comment --><p>ok</p>' ) );
    }

    public function testRemovesConditionalComments() : void
    {
        $this->assertSame( '<p>ok</p>', self::sanitize( '<!--[if IE]><script>alert(1)</script><![endif]--><p>ok</p>' ) );
    }


    // ── 3. Event handler removal ──

    public function testRemovesOnclick() : void
    {
        $result = Sane::html( '<div onclick="alert(1)">text</div>' );
        $this->assertStringNotContainsString( 'onclick', $result );
        $this->assertStringContainsString( 'text', $result );
    }

    public function testRemovesOnmouseover() : void
    {
        $result = Sane::html( '<a href="#" onmouseover="steal()">link</a>' );
        $this->assertStringNotContainsString( 'onmouseover', $result );
    }

    public function testRemovesOnerror() : void
    {
        $result = Sane::html( '<img src="x.png" onerror="alert(1)">' );
        $this->assertStringNotContainsString( 'onerror', $result );
    }

    public function testRemovesOnloadCaseInsensitive() : void
    {
        $result = Sane::html( '<body ONLOAD="alert(1)"><p>ok</p></body>' );
        $this->assertStringNotContainsString( 'onload', strtolower( $result ) );
    }

    public function testRemovesMultipleEventHandlers() : void
    {
        $result = Sane::html( '<div onclick="a()" onmouseover="b()" onfocus="c()">text</div>' );
        $this->assertStringNotContainsString( 'onclick', $result );
        $this->assertStringNotContainsString( 'onmouseover', $result );
        $this->assertStringNotContainsString( 'onfocus', $result );
    }


    // ── 4. Style attribute removal ──

    public function testRemovesStyleAttribute() : void
    {
        $result = Sane::html( '<div style="background:url(evil)">text</div>' );
        $this->assertStringNotContainsString( 'style', $result );
        $this->assertStringContainsString( 'text', $result );
    }


    // ── 5. Blocked URI schemes ──

    public function testBlocksJavascriptHref() : void
    {
        $result = Sane::html( '<a href="javascript:alert(1)">click</a>' );
        $this->assertStringNotContainsString( 'javascript', $result );
    }

    public function testBlocksJavascriptWithSpaces() : void
    {
        $result = Sane::html( '<a href="  javascript:alert(1)">click</a>' );
        $this->assertStringNotContainsString( 'javascript', $result );
    }

    public function testBlocksJavascriptCaseInsensitive() : void
    {
        $result = Sane::html( '<a href="JaVaScRiPt:alert(1)">click</a>' );
        $this->assertStringNotContainsString( 'href', $result );
    }

    public function testBlocksVbscript() : void
    {
        $result = Sane::html( '<a href="vbscript:MsgBox(1)">click</a>' );
        $this->assertStringNotContainsString( 'vbscript', $result );
    }

    public function testBlocksFileScheme() : void
    {
        $result = Sane::html( '<a href="file:///etc/passwd">click</a>' );
        $this->assertStringNotContainsString( 'file:', $result );
    }

    public function testBlocksBlobScheme() : void
    {
        $result = Sane::html( '<a href="blob:https://evil.com/uuid">click</a>' );
        $this->assertStringNotContainsString( 'blob:', $result );
    }

    public function testBlocksFilesystemScheme() : void
    {
        $result = Sane::html( '<a href="filesystem:https://evil.com/tmp/file">click</a>' );
        $this->assertStringNotContainsString( 'filesystem:', $result );
    }

    public function testAllowsHttpsHref() : void
    {
        $html = '<a href="https://example.com">click</a>';
        $this->assertStringContainsString( 'https://example.com', Sane::html( $html ) );
    }

    public function testAllowsRelativeHref() : void
    {
        $html = '<a href="/page">click</a>';
        $this->assertStringContainsString( '/page', Sane::html( $html ) );
    }


    // ── 5b. data: URI handling ──

    public function testAllowsDataImagePng() : void
    {
        $html = '<img src="data:image/png;base64,abc123">';
        $this->assertStringContainsString( 'data:image/png', Sane::html( $html ) );
    }

    public function testAllowsDataImageJpeg() : void
    {
        $html = '<img src="data:image/jpeg;base64,abc123">';
        $this->assertStringContainsString( 'data:image/jpeg', Sane::html( $html ) );
    }

    public function testAllowsDataImageGif() : void
    {
        $html = '<img src="data:image/gif;base64,abc123">';
        $this->assertStringContainsString( 'data:image/gif', Sane::html( $html ) );
    }

    public function testAllowsDataImageWebp() : void
    {
        $html = '<img src="data:image/webp;base64,abc123">';
        $this->assertStringContainsString( 'data:image/webp', Sane::html( $html ) );
    }

    public function testBlocksDataTextHtml() : void
    {
        $result = Sane::html( '<img src="data:text/html,<script>alert(1)</script>">' );
        $this->assertStringNotContainsString( 'data:text/html', $result );
    }

    public function testBlocksDataApplicationJavascript() : void
    {
        $result = Sane::html( '<img src="data:application/javascript,alert(1)">' );
        $this->assertStringNotContainsString( 'data:application/javascript', $result );
    }


    // ── 5c. srcset handling ──

    public function testAllowsSafeSrcset() : void
    {
        $html = '<img srcset="small.jpg 480w, large.jpg 800w">';
        $this->assertStringContainsString( 'srcset', Sane::html( $html ) );
    }

    public function testBlocksJavascriptInSrcset() : void
    {
        $result = Sane::html( '<img srcset="javascript:alert(1) 480w, ok.jpg 800w">' );
        $this->assertStringNotContainsString( 'srcset', $result );
    }


    // ── 6. DOM clobbering prevention ──

    public function testRemovesDangerousIdAttributes() : void
    {
        $result = Sane::html( '<div id="document">text</div>' );
        $this->assertStringNotContainsString( 'id=', $result );
    }

    public function testRemovesDangerousNameAttributes() : void
    {
        $result = Sane::html( '<form><input name="location"></form>' );
        $this->assertStringNotContainsString( 'name="location"', $result );
    }

    public function testKeepsSafeIdAttributes() : void
    {
        $result = Sane::html( '<div id="mywidget">text</div>' );
        $this->assertStringContainsString( 'id="mywidget"', $result );
    }

    public function testRemovesIdWindow() : void
    {
        $result = Sane::html( '<div id="window">text</div>' );
        $this->assertStringNotContainsString( 'id=', $result );
    }

    public function testRemovesNameSelf() : void
    {
        $result = Sane::html( '<form><input name="self"></form>' );
        $this->assertStringNotContainsString( 'name="self"', $result );
    }


    // ── 7. target="_blank" gets rel="noopener noreferrer" ──

    public function testAddsRelToTargetBlank() : void
    {
        $result = Sane::html( '<a href="https://example.com" target="_blank">link</a>' );
        $this->assertStringContainsString( 'rel="noopener noreferrer"', $result );
    }

    public function testDoesNotAddRelWithoutTargetBlank() : void
    {
        $result = Sane::html( '<a href="https://example.com">link</a>' );
        $this->assertStringNotContainsString( 'noopener', $result );
    }


    // ── Allow: true (non-URI tags) ──

    public function testAllowStyleTrue() : void
    {
        $html = '<p>ok</p><style>body{color:red}</style>';
        $result = Sane::html( $html, ['style' => true] );
        $this->assertStringContainsString( '<style>', $result );
        $this->assertStringContainsString( 'body{color:red}', $result );
    }

    public function testAllowSvgTrue() : void
    {
        $html = '<p>ok</p><svg width="100" height="100"><circle cx="50" cy="50" r="40"></circle></svg>';
        $result = Sane::html( $html, ['svg' => true] );
        $this->assertStringContainsString( '<svg', $result );
    }

    public function testAllowMathTrue() : void
    {
        $html = '<p>ok</p><math><mi>x</mi></math>';
        $result = Sane::html( $html, ['math' => true] );
        $this->assertStringContainsString( '<math>', $result );
    }

    public function testAllowTemplateTrue() : void
    {
        $html = '<p>ok</p><template><div>content</div></template>';
        $result = Sane::html( $html, ['template' => true] );
        $this->assertStringContainsString( '<template>', $result );
    }

    public function testAllowNoscriptTrue() : void
    {
        $html = '<p>ok</p><noscript>Enable JS</noscript>';
        $result = Sane::html( $html, ['noscript' => true] );
        $this->assertStringContainsString( '<noscript>', $result );
    }

    public function testAllowTrueStillStripsEventHandlers() : void
    {
        $html = '<svg onload="alert(1)" width="100"></svg>';
        $result = Sane::html( $html, ['svg' => true] );
        $this->assertStringNotContainsString( 'onload', $result );
        $this->assertStringContainsString( '<svg', $result );
    }

    public function testAllowTrueStillStripsStyleAttributes() : void
    {
        $html = '<svg style="position:fixed" width="100"></svg>';
        $result = Sane::html( $html, ['svg' => true] );
        $this->assertStringNotContainsString( 'style=', $result );
    }


    // ── Allow: URI prefix filtering for iframe ──

    public function testAllowIframeMatchingUri() : void
    {
        $html = '<p>ok</p><iframe src="https://www.youtube.com/embed/abc" width="560" height="315"></iframe>';
        $result = Sane::html( $html, ['iframe' => ['https://www.youtube.com/embed/']] );
        $this->assertStringContainsString( '<iframe', $result );
        $this->assertStringContainsString( 'src="https://www.youtube.com/embed/abc"', $result );
    }

    public function testAllowIframeNonMatchingUri() : void
    {
        $html = '<p>ok</p><iframe src="https://evil.com/page"></iframe>';
        $result = Sane::html( $html, ['iframe' => ['https://www.youtube.com/embed/']] );
        $this->assertStringNotContainsString( '<iframe', $result );
    }

    public function testAllowIframeStripsUnsafeAttributes() : void
    {
        $html = '<iframe src="https://www.youtube.com/embed/abc" onload="alert(1)" class="bad" width="560"></iframe>';
        $result = Sane::html( $html, ['iframe' => ['https://www.youtube.com/embed/']] );
        $this->assertStringNotContainsString( 'onload', $result );
        $this->assertStringNotContainsString( 'class=', $result );
        $this->assertStringContainsString( 'width="560"', $result );
    }

    public function testAllowIframeEnforcesSandbox() : void
    {
        $html = '<iframe src="https://www.youtube.com/embed/abc"></iframe>';
        $result = Sane::html( $html, ['iframe' => ['https://www.youtube.com/embed/']] );
        $this->assertStringContainsString( 'sandbox="allow-scripts allow-same-origin allow-popups"', $result );
    }

    public function testAllowIframeMultipleUris() : void
    {
        $uris = ['https://www.youtube.com/embed/', 'https://player.vimeo.com/'];

        $yt = '<iframe src="https://www.youtube.com/embed/abc"></iframe>';
        $this->assertStringContainsString( '<iframe', Sane::html( $yt, ['iframe' => $uris] ) );

        $vimeo = '<iframe src="https://player.vimeo.com/video/123"></iframe>';
        $this->assertStringContainsString( '<iframe', Sane::html( $vimeo, ['iframe' => $uris] ) );
    }

    public function testAllowIframeCaseInsensitiveMatch() : void
    {
        $html = '<iframe src="HTTPS://WWW.YOUTUBE.COM/embed/abc"></iframe>';
        $result = Sane::html( $html, ['iframe' => ['https://www.youtube.com/embed/']] );
        $this->assertStringContainsString( '<iframe', $result );
    }

    public function testAllowIframeRemovesWithoutSrc() : void
    {
        $html = '<p>ok</p><iframe></iframe>';
        $result = Sane::html( $html, ['iframe' => ['https://www.youtube.com/']] );
        $this->assertStringNotContainsString( '<iframe', $result );
    }

    public function testAllowIframeKeepsSafeAttrs() : void
    {
        $html = '<iframe src="https://www.youtube.com/embed/abc" width="560" height="315" title="Video" loading="lazy" allow="autoplay" allowfullscreen frameborder="0"></iframe>';
        $result = Sane::html( $html, ['iframe' => ['https://www.youtube.com/embed/']] );
        $this->assertStringContainsString( 'width="560"', $result );
        $this->assertStringContainsString( 'height="315"', $result );
        $this->assertStringContainsString( 'title="Video"', $result );
        $this->assertStringContainsString( 'loading="lazy"', $result );
        $this->assertStringContainsString( 'allow="autoplay"', $result );
        $this->assertStringContainsString( 'allowfullscreen', $result );
        $this->assertStringContainsString( 'frameborder="0"', $result );
    }


    // ── Allow: URI filtering for embed ──

    public function testAllowEmbedMatchingUri() : void
    {
        $html = '<p>ok</p><embed src="https://cdn.example.com/video.mp4" width="400" height="300">';
        $result = Sane::html( $html, ['embed' => ['https://cdn.example.com/']] );
        $this->assertStringContainsString( '<embed', $result );
        $this->assertStringContainsString( 'width="400"', $result );
    }

    public function testAllowEmbedNonMatchingUri() : void
    {
        $html = '<p>ok</p><embed src="https://evil.com/flash.swf">';
        $result = Sane::html( $html, ['embed' => ['https://cdn.example.com/']] );
        $this->assertStringNotContainsString( '<embed', $result );
    }

    public function testAllowEmbedStripsUnsafeAttrs() : void
    {
        $html = '<embed src="https://cdn.example.com/v.mp4" class="bad" width="400">';
        $result = Sane::html( $html, ['embed' => ['https://cdn.example.com/']] );
        $this->assertStringNotContainsString( 'class=', $result );
    }

    public function testAllowEmbedNoSandbox() : void
    {
        $html = '<embed src="https://cdn.example.com/v.mp4">';
        $result = Sane::html( $html, ['embed' => ['https://cdn.example.com/']] );
        $this->assertStringNotContainsString( 'sandbox', $result );
    }


    // ── Allow: URI filtering for object (uses data= attribute) ──

    public function testAllowObjectMatchingUri() : void
    {
        $html = '<p>ok</p><object data="https://cdn.example.com/widget.swf" width="400" height="300"></object>';
        $result = Sane::html( $html, ['object' => ['https://cdn.example.com/']] );
        $this->assertStringContainsString( '<object', $result );
        $this->assertStringContainsString( 'data="https://cdn.example.com/widget.swf"', $result );
    }

    public function testAllowObjectNonMatchingUri() : void
    {
        $html = '<p>ok</p><object data="https://evil.com/bad.swf"></object>';
        $result = Sane::html( $html, ['object' => ['https://cdn.example.com/']] );
        $this->assertStringNotContainsString( '<object', $result );
    }

    public function testAllowObjectNoSandbox() : void
    {
        $html = '<object data="https://cdn.example.com/w.swf"></object>';
        $result = Sane::html( $html, ['object' => ['https://cdn.example.com/']] );
        $this->assertStringNotContainsString( 'sandbox', $result );
    }


    // ── Allow: URI filtering for link (uses href= attribute) ──

    public function testAllowLinkMatchingUri() : void
    {
        $html = '<link rel="stylesheet" href="https://cdn.example.com/style.css"><p>ok</p>';
        $result = Sane::html( $html, ['link' => ['https://cdn.example.com/']] );
        $this->assertStringContainsString( '<link', $result );
        $this->assertStringContainsString( 'href="https://cdn.example.com/style.css"', $result );
    }

    public function testAllowLinkNonMatchingUri() : void
    {
        $html = '<link rel="stylesheet" href="https://evil.com/style.css"><p>ok</p>';
        $result = Sane::html( $html, ['link' => ['https://cdn.example.com/']] );
        $this->assertStringNotContainsString( '<link', $result );
    }

    public function testAllowLinkKeepsAllAttributes() : void
    {
        $html = '<link rel="stylesheet" href="https://cdn.example.com/style.css" media="screen"><p>ok</p>';
        $result = Sane::html( $html, ['link' => ['https://cdn.example.com/']] );
        $this->assertStringContainsString( 'rel="stylesheet"', $result );
        $this->assertStringContainsString( 'media="screen"', $result );
    }


    // ── Allow: URI filtering for script (uses src= attribute) ──

    public function testAllowScriptMatchingUri() : void
    {
        $html = '<p>ok</p><script src="https://cdn.example.com/app.js"></script>';
        $result = Sane::html( $html, ['script' => ['https://cdn.example.com/']] );
        $this->assertStringContainsString( '<script', $result );
    }

    public function testAllowScriptNonMatchingUri() : void
    {
        $html = '<p>ok</p><script src="https://evil.com/bad.js"></script>';
        $result = Sane::html( $html, ['script' => ['https://cdn.example.com/']] );
        $this->assertStringNotContainsString( '<script', $result );
    }


    // ── Allow: URI filtering for base (uses href= attribute) ──

    public function testAllowBaseMatchingUri() : void
    {
        $html = '<base href="https://example.com/"><p>ok</p>';
        $result = Sane::html( $html, ['base' => ['https://example.com/']] );
        $this->assertStringContainsString( '<base', $result );
    }

    public function testAllowBaseNonMatchingUri() : void
    {
        $html = '<base href="https://evil.com/"><p>ok</p>';
        $result = Sane::html( $html, ['base' => ['https://example.com/']] );
        $this->assertStringNotContainsString( '<base', $result );
    }


    // ── Defensive: URI prefixes for non-URI tags ──

    public function testUriPrefixesForStyleRemovesDefensively() : void
    {
        $html = '<p>ok</p><style>body{color:red}</style>';
        $result = Sane::html( $html, ['style' => ['https://example.com/']] );
        $this->assertStringNotContainsString( '<style>', $result );
    }

    public function testUriPrefixesForSvgRemovesDefensively() : void
    {
        $html = '<p>ok</p><svg width="100"></svg>';
        $result = Sane::html( $html, ['svg' => ['https://example.com/']] );
        $this->assertStringNotContainsString( '<svg', $result );
    }


    // ── Blocked URI in allowed iframe ──

    public function testAllowIframeBlocksJavascriptSrc() : void
    {
        $html = '<iframe src="javascript:alert(1)"></iframe>';
        $result = Sane::html( $html, ['iframe' => ['javascript:']] );
        $this->assertStringNotContainsString( '<iframe', $result );
    }


    // ── Mixed allow configuration ──

    public function testMixedAllowTrueAndUriPrefixes() : void
    {
        $html = '<style>body{color:red}</style><iframe src="https://www.youtube.com/embed/abc"></iframe><p>ok</p>';
        $result = Sane::html( $html, [
            'style' => true,
            'iframe' => ['https://www.youtube.com/embed/'],
        ] );
        $this->assertStringContainsString( '<style>', $result );
        $this->assertStringContainsString( '<iframe', $result );
        $this->assertStringContainsString( '<p>ok</p>', $result );
    }

    public function testAllowedTagsDoNotAffectOtherRemovedTags() : void
    {
        $html = '<iframe src="https://www.youtube.com/embed/abc"></iframe><script>alert(1)</script><p>ok</p>';
        $result = Sane::html( $html, ['iframe' => ['https://www.youtube.com/embed/']] );
        $this->assertStringContainsString( '<iframe', $result );
        $this->assertStringNotContainsString( '<script', $result );
    }


    // ── Empty input / edge cases ──

    public function testEmptyInput() : void
    {
        $this->assertSame( '', self::sanitize( '' ) );
    }

    public function testOnlyWhitespace() : void
    {
        $this->assertSame( '', self::sanitize( '   ' ) );
    }

    public function testNestedUnsafeElements() : void
    {
        $result = Sane::html( '<div><script><script>alert(1)</script></script></div>' );
        $this->assertStringNotContainsString( 'script', $result );
        $this->assertStringContainsString( '<div>', $result );
    }
}
