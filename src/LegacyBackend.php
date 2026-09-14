<?php

namespace Aimeos\Sanitizer;


/**
 * Masterminds (pure-PHP HTML5) sanitization path for PHP 8.0-8.3, where the
 * native parser is unavailable. Shares Policy and Tree with NativeBackend while
 * retaining corrections for differences between Masterminds and browser parsing.
 * Allowed template contents are sanitized here; the native
 * backend discards those contents because its API cannot reach them.
 */
class LegacyBackend
{
    private const MAX_ERRORS = 2048;

    /**
     * @param array<string, bool|list<string>> $allow
     */
    public static function sanitize( string $input, array $allow, bool $strict = false ) : string
    {
        $html5 = new \Masterminds\HTML5(['disable_html_ns' => true]);
        $doc = self::parse($input);
        if( $doc === null ) {
            return '';
        }

        $xpath = new \DOMXPath($doc);

        if( !Tree::prepare($doc) ) {
            return '';
        }

        // Collapse allowed noscript content before applying the shared policy;
        // convert CDATA nodes only when the marker is present.
        if( isset( $allow['noscript'] ) ) {
            self::collapseNoscript( $xpath, $doc );
        }
        if( stripos( $input, '<![cdata[' ) !== false ) {
            self::neutralizeCdata( $xpath, $doc );
        }

        Tree::sanitize( $doc, $allow, $strict );

        self::unwrapStructural( $xpath );

        return self::serializeBody( $doc, $html5 );
    }


    /** Parse with bounded errors and without unused source-position diagnostics. */
    private static function parse( string $input ) : ?\DOMDocument
    {
        $input = \Masterminds\HTML5\Parser\UTF8Utils::convertToUTF8('<!DOCTYPE html><html><body>' . $input . '</body></html>', 'UTF-8');
        // Match Scanner's null/control/noncharacter diagnostics after its UTF-8
        // conversion, before it allocates one array entry per error. Omit the
        // matches argument so counting itself uses constant auxiliary memory.
        // Keep the byte ranges aligned with UTF8Utils::checkForIllegalCodepoints.
        $errors = preg_match_all('/(?:
            [\x00-\x08\x0B\x0E-\x1F\x7F]
            | \xC2[\x80-\x9F]
            | \xED(?:\xA0[\x80-\xFF]|[\xA1-\xBE][\x00-\xFF]|\xBF[\x00-\xBF])
            | \xEF\xB7[\x90-\xAF]
            | \xEF\xBF[\xBE\xBF]
            | [\xF0-\xF4][\x8F-\xBF]\xBF[\xBE\xBF]
        )/x', $input);
        if( $errors === false || $errors > self::MAX_ERRORS ) {
            return null;
        }

        $events = new class(self::MAX_ERRORS - $errors) extends \Masterminds\HTML5\Parser\DOMTreeBuilder {
            /** @var int */
            private $remainingErrors;

            public function __construct( int $remainingErrors )
            {
                $this->remainingErrors = $remainingErrors;
                parent::__construct(false, ['disable_html_ns' => true]);
            }

            /**
             * @param string $msg
             * @param int $line
             * @param int $col
             */
            public function parseError( $msg, $line = 0, $col = 0 ) : void
            {
                // Count scanner, tokenizer and tree-repair errors together, without
                // retaining diagnostics that the sanitizer never consumes.
                if( --$this->remainingErrors < 0 ) {
                    throw new \OverflowException('HTML parse error budget exceeded');
                }
            }
        };
        $scanner = new \Masterminds\HTML5\Parser\Scanner($input, 'UTF-8');
        $parser = new class($scanner, $events) extends \Masterminds\HTML5\Parser\Tokenizer {
            protected function consumeData() : bool
            {
                if( $this->textMode === 0 ) {
                    // Finish references separately: upstream can otherwise decode
                    // one and discard a following literal '<' in the same call.
                    if( $this->scanner->current() === '&' ) {
                        $this->buffer($this->decodeCharacterReference());
                        return $this->carryOn;
                    }
                    $next = $this->scanner->peek();
                    if( $this->scanner->current() === '<' && !in_array($next, ['!', '/', '?'], true)
                        && !$this->is_alpha($next) ) {
                        $this->parseError('Illegal tag opening');
                        $this->buffer('<');
                        $this->scanner->consume();
                        return $this->carryOn;
                    }
                }
                return parent::consumeData();
            }

            /** @param string $quote */
            protected function quotedAttributeValue( $quote ) : string
            {
                // HTML keeps form feeds inside quoted values. Upstream treats
                // them as closing quotes, exposing attribute text as new markup.
                $value = '';
                while( ($text = $this->scanner->charsUntil($quote . '&')) !== false ) {
                    $value .= $text;
                    if( $this->scanner->current() !== '&' ) {
                        break;
                    }
                    $value .= $this->decodeCharacterReference(true);
                }
                $this->scanner->consume();
                return $value;
            }

            /**
             * @param string $msg
             * @return false
             */
            protected function parseError( $msg ) // @phpstan-ignore method.childReturnType (Upstream documents string but always returns false.)
            {
                // Upstream recomputes line/column by rescanning the input for
                // every error. Keep error recovery, but skip that quadratic work.
                $this->events->parseError('');
                return false;
            }
        };
        try {
            $parser->parse();
        } catch( \OverflowException $e ) {
            return null;
        }
        return $events->document();
    }


    /**
     * Collapses each kept <noscript> to its text content. Browsers with scripting
     * enabled parse noscript content as raw text, so a stray </noscript> in an
     * attribute would re-open parsing in the browser and free the following markup.
     */
    private static function collapseNoscript( \DOMXPath $xpath, \DOMDocument $doc ) : void
    {
        $nodes = $xpath->query('//noscript');
        if( $nodes === false ) {
            return;
        }
        foreach ($nodes as $node) {
            if( !$node instanceof \DOMElement || !$node->hasChildNodes() ) {
                continue;
            }
            $text = $node->textContent;
            while( $node->firstChild !== null ) {
                $node->removeChild( $node->firstChild );
            }
            if( $text !== '' ) {
                $node->appendChild( $doc->createTextNode( $text ) );
            }
        }
    }


    /**
     * Converts CDATA sections to text. HTML has no CDATA, so the parser keeps
     * "<![CDATA[...]]>" as a data node, but a browser treats "<![CDATA[" as a
     * bogus comment ending at the first ">", which would free trailing markup
     * (e.g. "<![CDATA[><img onerror=...>") as live elements.
     */
    private static function neutralizeCdata( \DOMXPath $xpath, \DOMDocument $doc ) : void
    {
        $nodes = $xpath->query('//text()');
        if( $nodes === false ) {
            return;
        }
        foreach ($nodes as $node) {
            if( $node instanceof \DOMCdataSection ) {
                if( $node->parentNode !== null ) {
                    $node->parentNode->replaceChild( $doc->createTextNode( $node->data ), $node );
                }
            }
        }
    }


    /**
     * Unwraps structural document elements (<html>/<head>/<body>/<title>/<frameset>)
     * the parser may have nested inside the wrapper body, so they don't leak into
     * the fragment output (and can't inject attributes into a host page's body/html
     * if the output is inlined). SVG/MathML <title> is a real child there, excluded.
     */
    private static function unwrapStructural( \DOMXPath $xpath ) : void
    {
        $nodes = $xpath->query('//body//html | //body//head | //body//body | //body//frameset'
            . ' | //body//title[not(ancestor::svg) and not(ancestor::math)]');
        if( $nodes === false ) {
            return;
        }
        foreach ($nodes as $node) {
            if( !$node instanceof \DOMElement || $node->parentNode === null ) {
                continue;
            }
            while( $node->firstChild !== null ) {
                $node->parentNode->insertBefore( $node->firstChild, $node );
            }
            $node->parentNode->removeChild( $node );
        }
    }


    /** Serialize the body children together, excluding the wrapper and its attributes. */
    private static function serializeBody( \DOMDocument $doc, \Masterminds\HTML5 $html5 ) : string
    {
        $body = $doc->getElementsByTagName('body')->item(0);
        if( !$body instanceof \DOMElement ) {
            return '';
        }
        // libxml's HTML serializer rewrites URI attributes (including IPv6 host
        // brackets). Use HTML5 serialization to preserve the URLs we checked.
        return $html5->saveHTML( $body->childNodes );
    }


}
