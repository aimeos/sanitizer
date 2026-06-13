<?php

namespace Aimeos\Sanitizer;


/**
 * Native (lexbor) sanitization path for PHP 8.4+. Mirrors LegacyBackend against
 * the spec-compliant \Dom API: elements are matched by lower-case local name
 * (HTML names are upper-cased and foreign content carries real namespaces here)
 * and serialization round-trips faithfully, so the parser-differential passes
 * still run but find nothing to fix. The one behavioural difference is an
 * allowed <template>: lexbor sequesters its children in an unreachable content
 * fragment, so this path drops that content (stripTemplateContent) rather than
 * sanitizing it in place — safe, but emptier than the legacy output.
 *
 * This class is only ever loaded when \Dom\HTMLDocument exists (Sane::html gates
 * the reference behind class_exists), so on PHP 8.0-8.3 its \Dom\* type hints are
 * never parsed or resolved.
 */
class NativeBackend
{
    /**
     * @param array<string, bool|list<string>> $allow
     */
    public static function sanitize( string $input, array $allow ) : string
    {
        $doc = \Dom\HTMLDocument::createFromString(
            '<!DOCTYPE html><html><body>' . $input . '</body></html>', LIBXML_NOERROR
        );
        $xpath = new \Dom\XPath( $doc );

        $removeSet = self::applyAllowList( $xpath, $allow );

        if( isset( $allow['noscript'] ) ) {
            self::collapseNoscript( $xpath, $doc );
        }
        if( stripos( $input, '<![cdata[' ) !== false ) {
            self::neutralizeCdata( $xpath, $doc );
        }

        self::sanitizeNodes( $xpath, $doc, $removeSet );

        if( isset( $allow['template'] ) ) {
            self::stripTemplateContent( $xpath );
        }
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
     * @param array<string, bool|list<string>> $allow
     * @return array<string, true>
     */
    private static function applyAllowList( \Dom\XPath $xpath, array $allow ) : array
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


    private static function collapseNoscript( \Dom\XPath $xpath, \Dom\HTMLDocument $doc ) : void
    {
        foreach ($xpath->document->querySelectorAll('noscript') as $node) {
            if( !$node->hasChildNodes() ) {
                continue;
            }
            $text = (string) $node->textContent;
            while( $node->firstChild !== null ) {
                $node->removeChild( $node->firstChild );
            }
            if( $text !== '' ) {
                $node->appendChild( $doc->createTextNode( $text ) );
            }
        }
    }


    /**
     * Defensive only: lexbor parses "<![CDATA[" in HTML as a bogus comment (removed
     * by removeComments) and CDATA in foreign content as escaped text, so it never
     * emits a \Dom\CdataSection here — unlike the libxml DOM the legacy path builds.
     * Kept as a guard in case a future build does, mirroring the legacy pass.
     */
    private static function neutralizeCdata( \Dom\XPath $xpath, \Dom\HTMLDocument $doc ) : void
    {
        foreach ($xpath->query('//text()') as $node) {
            if( $node instanceof \Dom\CdataSection ) {
                $node->parentNode?->replaceChild( $doc->createTextNode( $node->data ), $node );
            }
        }
    }


    /**
     * @param array<string, true> $removeSet
     */
    private static function sanitizeNodes( \Dom\XPath $xpath, \Dom\HTMLDocument $doc, array $removeSet ) : void
    {
        $animSet = array_flip( Policy::UNSAFE_SVG_ELEMENTS );
        $blockedSet = array_flip( Policy::BLOCKED_NAMES );
        $uriSet = array_flip( Policy::URI_ATTRIBUTES );

        if( $doc->documentElement !== null ) {
            self::removeComments( $doc->documentElement );
        }

        foreach ($xpath->query('//*') as $node) {
            if( !$node instanceof \Dom\Element ) {
                continue;
            }
            $tag = strtolower( (string) $node->localName );
            if( isset( $removeSet[$tag] ) || isset( $animSet[$tag] ) ) {
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
                    if( isset( $blockedSet[$attribute->value] ) ) {
                        $remove[] = $attribute;
                    }
                    continue;
                }
                if( $name === 'target' ) {
                    if( $tag === 'base' ) {
                        $remove[] = $attribute;
                    } elseif( !in_array( strtolower( trim( $attribute->value ) ), ['', '_self', '_parent', '_top'], true ) ) {
                        $newWindow = true;
                    }
                    continue;
                }

                // Match the full and local name so namespaced URI attributes such
                // as xlink:href (local name "href") are checked too. Unlike legacy
                // \DOMAttr, \Dom\Attr::$localName is never null, so no null guard.
                $local = $attribute->localName;
                if( !isset( $uriSet[$name] ) && !isset( $uriSet[$local] ) ) {
                    continue;
                }
                if (Policy::uriValueBlocked($local, trim($attribute->value))) {
                    $remove[] = $attribute;
                }
            }
            foreach ($remove as $attribute) {
                $node->removeAttributeNode($attribute);
            }

            if( $newWindow && ($tag === 'a' || $tag === 'area' || $tag === 'form') ) {
                $node->setAttribute('rel', Policy::mergeRel($node->getAttribute('rel') ?? ''));
            }
        }
    }


    private static function removeComments( \Dom\Node $node ) : void
    {
        $child = $node->firstChild;
        while( $child !== null ) {
            $next = $child->nextSibling;
            if( $child instanceof \Dom\Comment ) {
                $node->removeChild( $child );
            } elseif( $child->hasChildNodes() ) {
                self::removeComments( $child );
            }
            $child = $next;
        }
    }


    /**
     * Drops the content of every kept <template>. lexbor parses template children
     * into a content DocumentFragment that the \Dom API cannot reach (no "content"
     * property; "//*"/querySelectorAll don't descend into it) yet saveHtml() still
     * serializes — so, unlike the legacy path which sanitizes that content in place,
     * the only safe option here is to discard it, keeping the (already-sanitized)
     * template element. A shallow clone copies the element and its attributes but
     * not the unreachable content. Only reachable when template is allowed.
     */
    private static function stripTemplateContent( \Dom\XPath $xpath ) : void
    {
        foreach( $xpath->document->querySelectorAll('template') as $node ) {
            $node->parentNode?->replaceChild( $node->cloneNode(false), $node );
        }
    }


    private static function checkMetaRefresh( \Dom\XPath $xpath ) : void
    {
        foreach ($xpath->document->querySelectorAll('meta[content]') as $node) {
            if( Policy::metaRefreshBlocked($node->getAttribute('content') ?? '', $node->getAttribute('http-equiv') ?? '') ) {
                $node->removeAttribute('content');
            }
        }
    }


    private static function dropRawTextBreakouts( \Dom\XPath $xpath ) : void
    {
        foreach( $xpath->document->querySelectorAll('style, script') as $node ) {
            $tag = strtolower( (string) $node->localName );
            if( preg_match( '#</' . $tag . '[\s/>]#i', (string) $node->textContent ) ) {
                $node->parentNode?->removeChild( $node );
            }
        }
    }


    private static function dropInlineScripts( \Dom\XPath $xpath ) : void
    {
        foreach ($xpath->document->querySelectorAll('script') as $node) {
            if( trim($node->getAttribute('src') ?? '') === '' ) {
                $node->parentNode?->removeChild($node);
            }
        }
    }


    private static function unwrapStructural( \Dom\XPath $xpath ) : void
    {
        $nodes = $xpath->query('//*[local-name()="body"]//*[local-name()="html" or local-name()="head"'
            . ' or local-name()="body" or local-name()="frameset" or (local-name()="title"'
            . ' and not(ancestor::*[local-name()="svg"]) and not(ancestor::*[local-name()="math"]))]');
        foreach ($nodes as $node) {
            if( !$node instanceof \Dom\Element || $node->parentNode === null ) {
                continue;
            }
            while( $node->firstChild !== null ) {
                $node->parentNode->insertBefore( $node->firstChild, $node );
            }
            $node->parentNode->removeChild( $node );
        }
    }


    private static function serializeBody( \Dom\HTMLDocument $doc ) : string
    {
        $body = $doc->getElementsByTagName('body')->item(0);
        if( !$body instanceof \Dom\Element ) {
            return '';
        }
        while( $body->attributes->length > 0 ) {
            $attr = $body->attributes->item(0);
            if( !$attr instanceof \Dom\Attr ) {
                break;
            }
            $body->removeAttributeNode( $attr );
        }
        $html = (string) preg_replace('#^\s*<body[^>]*>#i', '', $doc->saveHtml( $body ));
        return (string) preg_replace('#</body>\s*$#i', '', $html);
    }


    /**
     * @param list<string> $uris
     */
    private static function filterByUri( \Dom\XPath $xpath, string $tag, array $uris ) : void
    {
        $uriAttr = Policy::TAG_URI_ATTR[$tag] ?? null;
        $nodes = $xpath->document->querySelectorAll($tag);

        if( $uriAttr === null )
        {
            foreach( $nodes as $node ) {
                $node->parentNode?->removeChild( $node );
            }
            return;
        }

        foreach( $nodes as $node )
        {
            $val = trim( $node->getAttribute( $uriAttr ) ?? '' );
            if( !$val || !Policy::isAllowedUri( $val, $uris ) || Policy::isBlockedUri( $val ) )
            {
                $node->parentNode?->removeChild( $node );
                continue;
            }
            self::hardenAttributes( $node, $tag );
        }
    }


    private static function restrictBaseHref( \Dom\XPath $xpath ) : void
    {
        foreach( $xpath->document->querySelectorAll('base[href]') as $node ) {
            if( Policy::baseHrefCrossOrigin( $node->getAttribute('href') ?? '' ) ) {
                $node->removeAttribute('href');
            }
        }
    }


    private static function hardenAllowed( \Dom\XPath $xpath, string $tag ) : void
    {
        if( !isset( Policy::SAFE_ATTRS[$tag] ) ) {
            return;
        }
        foreach( $xpath->document->querySelectorAll($tag) as $node ) {
            self::hardenAttributes( $node, $tag );
        }
    }


    private static function hardenAttributes( \Dom\Element $node, string $tag ) : void
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

        if( $tag === 'iframe' && $node->hasAttribute( 'allow' ) ) {
            $allow = Policy::filterAllowFeatures( $node->getAttribute( 'allow' ) ?? '' );
            if( $allow !== '' ) {
                $node->setAttribute( 'allow', $allow );
            } else {
                $node->removeAttribute( 'allow' );
            }
        }

        if( in_array( $tag, ['iframe', 'frame'], true ) ) {
            $node->setAttribute( 'sandbox', 'allow-scripts allow-popups' );
        }
    }
}
