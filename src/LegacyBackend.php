<?php

namespace Aimeos\Sanitizer;


/**
 * Masterminds (pure-PHP HTML5) sanitization path for PHP 8.0-8.3, where the
 * native parser is unavailable. Identical behaviour to NativeBackend, modulo
 * cosmetic serialization differences.
 *
 * Parses with the HTML5 algorithm (matching browsers) so the
 * parse → sanitize → serialize → browser-reparse cycle stays consistent and
 * can't be exploited via parser-differential mutation XSS the way the libxml
 * HTML4 parser could.
 */
class LegacyBackend
{
    /**
     * @param array<string, bool|list<string>> $allow
     */
    public static function sanitize( string $input, array $allow ) : string
    {
        $html5 = new \Masterminds\HTML5(['disable_html_ns' => true]);
        $doc = $html5->loadHTML('<!DOCTYPE html><html><body>' . $input . '</body></html>');

        $xpath = new \DOMXPath($doc);

        $removeSet = self::applyAllowList( $xpath, $allow );

        // <noscript>/<meta>/<script> only survive removal when explicitly
        // allowed, so their dedicated passes run only then; CDATA only when the
        // marker is present.
        if( isset( $allow['noscript'] ) ) {
            self::collapseNoscript( $xpath, $doc );
        }
        if( stripos( $input, '<![cdata[' ) !== false ) {
            self::neutralizeCdata( $xpath, $doc );
        }

        self::sanitizeNodes( $xpath, $doc, $removeSet );

        if( isset( $allow['style'] ) || isset( $allow['script'] ) ) {
            self::dropRawTextBreakouts( $xpath );
        }
        if( isset( $allow['meta'] ) ) {
            self::checkMetaRefresh( $xpath );
        }
        if( isset( $allow['script'] ) ) {
            self::dropInlineScripts( $xpath );
        }
        self::unwrapStructural( $xpath );

        return self::serializeBody( $doc );
    }


    /**
     * Opts the elements in $allow back in (hardened) and returns the still-blocked
     * element names, keyed by tag, for removal in the main pass.
     *
     * @param array<string, bool|list<string>> $allow
     * @return array<string, true>
     */
    private static function applyAllowList( \DOMXPath $xpath, array $allow ) : array
    {
        $removeSet = [];
        foreach (Policy::REMOVE_ELEMENTS as $tag) {
            if( isset( $allow[$tag] ) ) {
                if( $allow[$tag] === true ) {
                    self::hardenAllowed( $xpath, $tag );
                    if( $tag === 'base' ) {
                        self::restrictBaseHref( $xpath );
                    }
                    continue;
                }
                self::filterByUri( $xpath, $tag, array_values( array_filter( (array) $allow[$tag], 'is_string' ) ) );
                continue;
            }
            $removeSet[$tag] = true;
        }
        return $removeSet;
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
                $node->parentNode?->replaceChild( $doc->createTextNode( $node->data ), $node );
            }
        }
    }


    /**
     * Strips comments (via a linear DOM walk) and then makes a single pass over
     * every element: removes blocked and script-bearing SVG elements and, on each
     * survivor, strips event-handler/style/dangerous-URI and clobbering id/name
     * attributes and adds rel="noopener noreferrer" to links opening a new context.
     *
     * @param array<string, true> $removeSet
     */
    private static function sanitizeNodes( \DOMXPath $xpath, \DOMDocument $doc, array $removeSet ) : void
    {
        $animSet = array_flip( Policy::UNSAFE_SVG_ELEMENTS );
        $blockedSet = array_flip( Policy::BLOCKED_NAMES );
        $uriSet = array_flip( Policy::URI_ATTRIBUTES );

        // Remove comments with a linear DOM walk: the "//comment()" xpath is
        // ~O(n^2) in libxml on comment-heavy input (a cheap DoS), unlike "//*".
        if( $doc->documentElement !== null ) {
            self::removeComments( $doc->documentElement );
        }

        $nodes = $xpath->query('//*');
        if( $nodes === false ) {
            return;
        }
        foreach ($nodes as $node) {
            if( !$node instanceof \DOMElement ) {
                continue;
            }
            $tag = $node->nodeName;
            if( isset( $removeSet[$tag] ) || isset( $animSet[strtolower($tag)] ) ) {
                $node->parentNode?->removeChild($node);
                continue;
            }

            $remove = [];
            $newWindow = false;
            foreach ($node->attributes as $attribute) {
                $name = $attribute->name;

                if( stripos($name, 'on') === 0 || $name === 'style' ) {
                    $remove[] = $attribute;
                    continue;
                }
                if( $name === 'id' || $name === 'name' ) {
                    // DOM clobbering: drop id/name shadowing a window/document property
                    if( isset( $blockedSet[$attribute->value] ) ) {
                        $remove[] = $attribute;
                    }
                    continue;
                }
                if( $name === 'target' ) {
                    // A <base target> sets the default browsing context for every
                    // link in the document, so a tabnabbing target there can't be
                    // hardened per link — drop it. Any other target that opens a
                    // separate context (anything but _self/_parent/_top, matched
                    // case-insensitively, incl. "_blank" and named windows) gets the
                    // rel="noopener noreferrer" hardening below.
                    if( $tag === 'base' ) {
                        $remove[] = $attribute;
                    } elseif( !in_array( strtolower( trim( $attribute->value ) ), ['', '_self', '_parent', '_top'], true ) ) {
                        $newWindow = true;
                    }
                    continue;
                }

                // Match the full and local name so namespaced URI attributes
                // such as xlink:href (local name "href") are checked too.
                $local = $attribute->localName;
                if( !isset( $uriSet[$name] ) && ( $local === null || !isset( $uriSet[$local] ) ) ) {
                    continue;
                }
                // The attribute value is already entity-decoded to what the
                // browser sees, so it is checked as-is.
                if (Policy::uriValueBlocked($local, trim($attribute->value))) {
                    $remove[] = $attribute;
                }
            }
            foreach ($remove as $attribute) {
                $node->removeAttributeNode($attribute);
            }

            if( $newWindow && ($tag === 'a' || $tag === 'area' || $tag === 'form') ) {
                $node->setAttribute('rel', Policy::mergeRel($node->getAttribute('rel')));
            }
        }
    }


    /**
     * Recursively removes every comment node under $node. Used instead of an
     * "//comment()" xpath, which libxml evaluates in ~O(n^2) on comment-heavy input.
     */
    private static function removeComments( \DOMNode $node ) : void
    {
        $child = $node->firstChild;
        while( $child !== null ) {
            $next = $child->nextSibling;
            if( $child instanceof \DOMComment ) {
                $node->removeChild( $child );
            } elseif( $child->hasChildNodes() ) {
                self::removeComments( $child );
            }
            $child = $next;
        }
    }


    /**
     * Neutralizes <meta http-equiv="refresh"> redirects whose URL uses a blocked
     * scheme. Only reachable when meta is allowed.
     */
    private static function checkMetaRefresh( \DOMXPath $xpath ) : void
    {
        $nodes = $xpath->query('//meta[@content]');
        if( $nodes === false ) {
            return;
        }
        foreach ($nodes as $node) {
            if( $node instanceof \DOMElement
                && Policy::metaRefreshBlocked($node->getAttribute('content'), $node->getAttribute('http-equiv'))
            ) {
                $node->removeAttribute('content');
            }
        }
    }


    /**
     * Drops kept <style>/<script> elements whose raw-text content would let a
     * browser break out of the element. The Masterminds parser only ends these
     * raw-text elements on the exact "</style>"/"</script>", but the HTML5 spec
     * (and every browser) also ends them at "</style"/"</script" followed by
     * whitespace, "/" or ">". Such a stray end tag therefore stays inert raw text
     * here — so the markup after it is never sanitized — while libxml emits
     * style/script content unescaped, freeing it as live elements on reparse
     * (e.g. "<style></style/><img src=x onerror=alert(1)>"). Only reachable when
     * style or script is allowed.
     */
    private static function dropRawTextBreakouts( \DOMXPath $xpath ) : void
    {
        $nodes = $xpath->query('//style | //script');
        if( $nodes === false ) {
            return;
        }
        foreach( $nodes as $node ) {
            if( !$node instanceof \DOMElement ) {
                continue;
            }
            $tag = strtolower( $node->nodeName );
            if( preg_match( '#</' . $tag . '[\s/>]#i', $node->textContent ) ) {
                $node->parentNode?->removeChild( $node );
            }
        }
    }


    /**
     * Drops inline scripts; an allowed <script> is only kept when it loads from an
     * external src that survived the scheme check. Only reachable when script is
     * allowed.
     */
    private static function dropInlineScripts( \DOMXPath $xpath ) : void
    {
        $nodes = $xpath->query('//script');
        if( $nodes === false ) {
            return;
        }
        foreach ($nodes as $node) {
            if( $node instanceof \DOMElement && trim($node->getAttribute('src')) === '' ) {
                $node->parentNode?->removeChild($node);
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


    /**
     * Returns the sanitized content of the wrapper body. Its own attributes are
     * never part of the output and are cleared so the wrapper-tag strip stays
     * robust even if the parser merged input <body> attributes onto it; serializing
     * once is much faster than a saveHTML() call per child for many top-level nodes.
     */
    private static function serializeBody( \DOMDocument $doc ) : string
    {
        $body = $doc->getElementsByTagName('body')->item(0);
        if( !$body instanceof \DOMElement ) {
            return '';
        }
        while( $body->attributes->length > 0 ) {
            $attr = $body->attributes->item(0);
            if( !$attr instanceof \DOMAttr ) {
                break;
            }
            $body->removeAttributeNode( $attr );
        }
        // Serialize with libxml's saveHTML (a native DOMDocument method): the tree
        // was already built by the HTML5 parser, and libxml's serializer is ~25x
        // faster and escapes attribute/text content safely (it picks a
        // non-conflicting quote delimiter and entity-encodes <, >, & and the
        // delimiter), so the browser re-parses the output identically.
        $html = (string) preg_replace('#^\s*<body[^>]*>#i', '', (string) $doc->saveHTML( $body ));
        return (string) preg_replace('#</body>\s*$#i', '', $html);
    }


    /**
     * @param list<string> $uris
     */
    private static function filterByUri( \DOMXPath $xpath, string $tag, array $uris ) : void
    {
        $uriAttr = Policy::TAG_URI_ATTR[$tag] ?? null;
        $nodes = $xpath->query("//{$tag}");

        if( $nodes === false ) {
            return;
        }

        // Tag has no URI attribute — remove all instances defensively
        if( $uriAttr === null )
        {
            foreach( $nodes as $node ) {
                if( $node instanceof \DOMNode ) {
                    $node->parentNode?->removeChild( $node );
                }
            }
            return;
        }

        foreach( $nodes as $node )
        {
            if( !$node instanceof \DOMElement ) {
                continue;
            }

            $val = trim( $node->getAttribute( $uriAttr ) );

            if( !$val || !Policy::isAllowedUri( $val, $uris ) || Policy::isBlockedUri( $val ) )
            {
                $node->parentNode?->removeChild( $node );
                continue;
            }

            // Strip attributes and enforce sandbox only for embedding tags
            self::hardenAttributes( $node, $tag );
        }
    }


    /**
     * Removes an absolute or protocol-relative href from <base> elements allowed
     * unconditionally, so they cannot repoint every relative URL to another
     * origin. Bases allowed via a URL-prefix list are already origin-restricted.
     */
    private static function restrictBaseHref( \DOMXPath $xpath ) : void
    {
        $nodes = $xpath->query('//base[@href]');
        if( $nodes === false ) {
            return;
        }

        foreach( $nodes as $node ) {
            if( $node instanceof \DOMElement && Policy::baseHrefCrossOrigin( $node->getAttribute('href') ) ) {
                $node->removeAttribute('href');
            }
        }
    }


    /**
     * Applies attribute hardening to every instance of an embedding tag that was
     * allowed unconditionally (allow[$tag] === true), so an allowed iframe still
     * cannot keep a script-executing srcdoc attribute or skip its sandbox.
     */
    private static function hardenAllowed( \DOMXPath $xpath, string $tag ) : void
    {
        if( !isset( Policy::SAFE_ATTRS[$tag] ) ) {
            return;
        }

        $nodes = $xpath->query( "//{$tag}" );
        if( $nodes === false ) {
            return;
        }

        foreach( $nodes as $node ) {
            if( $node instanceof \DOMElement ) {
                self::hardenAttributes( $node, $tag );
            }
        }
    }


    /**
     * Removes every attribute not on the per-tag allow-list from an embedding
     * element and enforces a sandbox where applicable. Embedding tags can carry
     * script-executing attributes (e.g. iframe's srcdoc), so anything outside
     * the allow-list is dropped.
     */
    private static function hardenAttributes( \DOMElement $node, string $tag ) : void
    {
        if( !isset( Policy::SAFE_ATTRS[$tag] ) ) {
            return;
        }

        $safe = Policy::SAFE_ATTRS[$tag];
        $attrsToRemove = [];

        foreach( $node->attributes as $attr ) {
            if( !in_array( $attr->name, $safe, true ) ) {
                $attrsToRemove[] = $attr;
            }
        }

        foreach( $attrsToRemove as $attr ) {
            $node->removeAttributeNode( $attr );
        }

        // Restrict the iframe Permissions-Policy "allow" attribute to safe
        // features so an allowed embed can't request e.g. camera or microphone.
        if( $tag === 'iframe' && $node->hasAttribute( 'allow' ) ) {
            $allow = Policy::filterAllowFeatures( $node->getAttribute( 'allow' ) );
            if( $allow !== '' ) {
                $node->setAttribute( 'allow', $allow );
            } else {
                $node->removeAttribute( 'allow' );
            }
        }

        if( in_array( $tag, ['iframe', 'frame'], true ) ) {
            // No allow-same-origin: together with allow-scripts it lets
            // same-origin framed content remove its own sandbox and escape.
            // (Browsers ignore the attribute on <frame>, which cannot be
            // sandboxed — avoid allowing <frame> for untrusted origins.)
            $node->setAttribute( 'sandbox', 'allow-scripts allow-popups' );
        }
    }
}
