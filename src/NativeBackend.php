<?php

namespace Aimeos\Sanitizer;


/**
 * Native (lexbor) sanitization path for PHP 8.4+. Mirrors LegacyBackend against
 * the spec-compliant \Dom API: elements are matched by lower-case local name
 * (HTML names are upper-cased and foreign content carries real namespaces here).
 * Parser-differential guards are retained on both backends. One difference is an
 * allowed <template>: lexbor sequesters its children in an unreachable content
 * fragment, so this path drops that content (stripTemplateContent) rather than
 * sanitizing it in place — safe, but emptier than the legacy output.
 *
 * Sane dispatches here only when \Dom\HTMLDocument exists.
 */
class NativeBackend
{
    /**
     * @param array<string, bool|list<string>> $allow
     */
    public static function sanitize( string $input, array $allow, bool $strict = false ) : string
    {
        // Input declarations must not select a different output encoding: bytes
        // emitted in ISO-2022-JP can become live markup in a UTF-8 host document.
        $doc = \Dom\HTMLDocument::createFromString(
            '<!DOCTYPE html><html><body>' . $input . '</body></html>', LIBXML_NOERROR, 'UTF-8'
        );
        $xpath = new \Dom\XPath( $doc );

        if( !Tree::prepare($doc) ) {
            return '';
        }

        if( isset( $allow['noscript'] ) ) {
            self::collapseNoscript( $xpath, $doc );
        }

        Tree::sanitize( $doc, $allow, $strict );

        if( isset( $allow['template'] ) ) {
            self::stripTemplateContent( $xpath );
        }
        self::unwrapStructural( $xpath );

        return self::serializeBody( $doc );
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
        return $body instanceof \Dom\Element ? $body->innerHTML : '';
    }


}
