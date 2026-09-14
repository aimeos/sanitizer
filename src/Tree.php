<?php

namespace Aimeos\Sanitizer;


/** Shared DOM operations supported by both the legacy and native APIs. @internal */
class Tree
{
    /**
     * Check the actual parsed tree and remove comments without recursion or XPath.
     *
     * @param \DOMNode|\Dom\Node $root
     */
    public static function prepare( $root ) : bool
    {
        $node = $root;
        $depth = $nodes = $attrWork = $attrTotal = 0;
        while( true ) {
            $element = $node instanceof \DOMElement || $node instanceof \Dom\Element;
            if( $element ) {
                $attrs = $node->attributes->length;
                $attrWork += $attrs * $attrs;
                $attrTotal += $attrs;
            }
            // Count comments before removal and include text/CDATA/PI nodes.
            // Only elements affect the nesting-depth limit.
            if( Limits::treeExceeds($element ? $depth : 0, ++$nodes, $attrWork, $attrTotal) ) {
                return false;
            }
            if( $node->firstChild !== null ) {
                $node = $node->firstChild;
                $depth++;
                continue;
            }
            $comment = $node->nodeType === XML_COMMENT_NODE ? $node : null;
            while( $node !== $root && $node->nextSibling === null ) {
                $parent = $node->parentNode;
                if( $parent === null ) {
                    return false;
                }
                $node = $parent;
                $depth--;
            }
            $next = $node === $root ? null : $node->nextSibling;
            if( $comment !== null && $comment->parentNode !== null ) {
                $comment->parentNode->removeChild( $comment );
            }
            if( $next === null ) {
                return true;
            }
            $node = $next;
        }
    }


    /**
     * Filter descendants in document order, skipping a branch as soon as its
     * element is removed. The full tree budget must already have been checked.
     *
     * @param \DOMNode|\Dom\Node $root
     * @param array<string, bool|list<string>> $allow
     */
    public static function sanitize( $root, array $allow, bool $strict ) : void
    {
        $node = $root->firstChild;
        while( $node !== null ) {
            // Save the route out before filtering can detach this element.
            $next = $node->nextSibling;
            $parent = $node->parentNode;
            if( $node instanceof \DOMElement || $node instanceof \Dom\Element ) {
                self::sanitizeElement($node, $allow, $strict);
            }
            if( $node->parentNode !== null && $node->firstChild !== null ) {
                $node = $node->firstChild;
                continue;
            }
            while( $next === null && $parent !== null && $parent !== $root ) {
                $next = $parent->nextSibling;
                $parent = $parent->parentNode;
            }
            $node = $next;
        }
    }


    /**
     * @param \DOMElement|\Dom\Element $node
     * @param array<string, bool|list<string>> $allow
     */
    public static function sanitizeElement( $node, array $allow, bool $strict ) : void
    {
        $tag = strtolower( $node->tagName );
        // Native HTML tagName is upper-case; foreign/prefixed names stay distinct.
        $uriAttr = Policy::TAG_URI_ATTR[$tag] ?? null;
        $uri = $uriAttr === null ? '' : trim($node->getAttribute($uriAttr) ?? '');
        $refreshUrl = null;
        if( $tag === 'meta' && strcasecmp($node->getAttribute('http-equiv') ?? '', 'refresh') === 0 ) {
            $refreshUrl = Policy::metaRefreshUrl($node->getAttribute('content') ?? '');
            $uri = $refreshUrl ?? '';
        }
        $structural = in_array( $tag, ['html', 'head', 'body', 'frameset'], true );
        if( ($strict && !in_array($node->namespaceURI, [null, '', 'http://www.w3.org/1999/xhtml'], true))
            || (!$structural && Policy::elementBlocked($tag, $uri, $allow, $strict)) ) {
            if( $node->parentNode !== null ) {
                $node->parentNode->removeChild( $node );
            }
            return;
        }

        $remove = [];
        foreach( $node->attributes as $attr ) {
            if( (isset(Policy::SAFE_ATTRS[$tag]) && !in_array($attr->name, Policy::SAFE_ATTRS[$tag], true))
                || ($tag === 'base' && $attr->name === 'href' && ($allow['base'] ?? false) === true
                    && Policy::baseHrefCrossOrigin($attr->value))
                || Policy::attributeBlocked($tag, $attr->name, $attr->localName, $attr->value, $strict) ) {
                $remove[] = $attr;
            }
        }
        foreach( $remove as $attr ) {
            $node->removeAttributeNode( $attr );
        }

        // SVG scripts use href, not HTML's src. The legacy parser discards
        // unprefixed namespaces, so check ancestry as well as the namespace.
        // Keep script exceptions confined to ordinary HTML on both backends.
        if( $tag === 'script' && (trim($node->getAttribute('src') ?? '') === '' || self::inForeignContent($node)) ) {
            if( $node->parentNode !== null ) {
                $node->parentNode->removeChild( $node );
            }
            return;
        }
        // Masterminds may retain malformed raw-text end tags which browsers
        // recognize on reparse. Preserve this guard for allowed style/script.
        if( in_array($tag, ['style', 'script'], true)
            && preg_match('#</' . $tag . '[\s/>]#i', (string) $node->textContent) ) {
            if( $node->parentNode !== null ) {
                $node->parentNode->removeChild( $node );
            }
            return;
        }
        if( $refreshUrl !== null && Policy::isBlockedUri($refreshUrl) ) {
            $node->removeAttribute('content');
        }

        if( in_array($tag, ['a', 'area', 'form'], true)
            && Policy::opensNewContext($node->getAttribute('target') ?? '') ) {
            $node->setAttribute('rel', Policy::mergeRel($node->getAttribute('rel') ?? ''));
        }
        if( $tag === 'iframe' && $node->hasAttribute('allow') ) {
            $features = Policy::filterAllowFeatures($node->getAttribute('allow') ?? '');
            if( $features === '' ) {
                $node->removeAttribute('allow');
            } else {
                $node->setAttribute('allow', $features);
            }
        }
        // Only iframe supports sandbox. Do not imply that legacy frames are isolated.
        if( $tag === 'iframe' ) {
            $node->setAttribute('sandbox', 'allow-scripts allow-popups');
        }
    }


    /** @param \DOMElement|\Dom\Element $node */
    private static function inForeignContent( $node ) : bool
    {
        do {
            if( !in_array($node->namespaceURI, [null, '', 'http://www.w3.org/1999/xhtml'], true)
                || in_array(strtolower($node->tagName), ['svg', 'math'], true) ) {
                return true;
            }
            $node = $node->parentNode;
        } while( $node instanceof \DOMElement || $node instanceof \Dom\Element );

        return false;
    }
}
