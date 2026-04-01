<?php

namespace Aimeos\Sanitizer;


class Sane
{
    // Unsafe elements to remove completely
    /** @var list<string> */
    private static array $removeElements = ['base', 'embed', 'form', 'frame', 'iframe', 'link', 'math', 'meta', 'noscript', 'object', 'script', 'style', 'svg', 'template'];

    // Attributes that may contain URIs
    /** @var list<string> */
    private static array $uriAttributes = [
        'href', 'src', 'xlink:href', 'formaction', 'action', 'background', 'poster', 'ping', 'srcset'
    ];

    // Disallowed URI schemes
    /** @var list<string> */
    private static array $blockedSchemes = ['javascript', 'vbscript', 'file', 'filesystem', 'blob'];

    // Allowed MIME types for data: URIs
    /** @var list<string> */
    private static array $allowedDataMimes = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

    // Tag to URI attribute mapping
    /** @var array<string, string> */
    private static array $tagUriAttr = [
        'iframe' => 'src',
        'embed'  => 'src',
        'frame'  => 'src',
        'script' => 'src',
        'object' => 'data',
        'link'   => 'href',
        'form'   => 'action',
        'base'   => 'href',
        'meta'   => 'content',
    ];

    // Safe attributes per embedding tag (also used to identify embedding tags)
    /** @var array<string, list<string>> */
    private static array $safeAttrs = [
        'embed'  => ['src', 'width', 'height', 'type', 'title'],
        'iframe' => ['src', 'width', 'height', 'title', 'loading', 'allow', 'allowfullscreen', 'frameborder', 'sandbox'],
        'frame'  => ['src', 'name', 'title', 'frameborder', 'scrolling'],
        'object' => ['data', 'width', 'height', 'type', 'title'],
    ];

    /** @var list<string> */
    private static array $blockedNames = [
        'location', 'window', 'document', 'frames', 'self', 'parent', 'top',
        'opener', 'alert', 'confirm', 'prompt', 'navigator', 'history', 'event',
        'console', 'frames', 'length', 'content', 'forms', 'images', 'anchors'
    ];


    /**
     * @param array<string, bool|list<string>> $allow
     */
    public static function html( string $input, array $allow = [] ) : string
    {
        $doc = new \DOMDocument();

        libxml_use_internal_errors(true);
        $doc->loadHTML('<?xml version="1.0" encoding="utf-8"?>' . $input, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        $doc->normalizeDocument();
        libxml_clear_errors();

        $xpath = new \DOMXPath($doc);

        // --- 1. Remove all unsafe elements (skip those with allowed URIs) ---
        foreach (self::$removeElements as $tag) {
            if( isset( $allow[$tag] ) ) {
                if( $allow[$tag] === true ) {
                    continue;
                }
                self::filterByUri( $xpath, $tag, array_values( array_filter( (array) $allow[$tag], 'is_string' ) ) );
                continue;
            }
            $nodes = $xpath->query("//{$tag}");
            if( $nodes === false ) {
                continue;
            }
            foreach ($nodes as $node) {
                if( $node instanceof \DOMNode ) {
                    $node->parentNode?->removeChild($node);
                }
            }
        }

        // --- 2. Remove HTML comments ---
        $comments = $xpath->query('//comment()');
        if( $comments !== false ) {
            foreach ($comments as $comment) {
                if( $comment instanceof \DOMNode ) {
                    $comment->parentNode?->removeChild($comment);
                }
            }
        }

        // --- 3. Remove all on* event handler attributes ---
        $allElements = $xpath->query('//*');
        if( $allElements !== false ) {
            foreach ($allElements as $node) {
                if( !$node instanceof \DOMElement ) {
                    continue;
                }
                $attrsToRemove = [];
                foreach ($node->attributes as $attribute) {
                    if (stripos($attribute->name, 'on') === 0) {
                        $attrsToRemove[] = $attribute->name;
                    }
                }
                foreach ($attrsToRemove as $name) {
                    $node->removeAttribute($name);
                }
            }
        }

        // --- 4. Remove all style attributes ---
        $styleNodes = $xpath->query('//*[@style]');
        if( $styleNodes !== false ) {
            foreach ($styleNodes as $node) {
                if( $node instanceof \DOMElement ) {
                    $node->removeAttribute('style');
                }
            }
        }

        // --- 5. Remove attributes with disallowed URI schemes ---
        foreach (self::$uriAttributes as $attr) {
            $nodesWithAttr = $xpath->query('//*[@*[local-name()="' . $attr . '"]]');
            if( $nodesWithAttr === false ) {
                continue;
            }
            foreach ($nodesWithAttr as $node) {
                if( !$node instanceof \DOMElement ) {
                    continue;
                }
                $value = html_entity_decode($node->getAttribute($attr), ENT_QUOTES | ENT_HTML5);
                $value = trim($value);

                if ($attr === 'srcset') {
                    foreach (preg_split('/\s*,\s*/', $value) ?: [] as $entry) {
                        $url = (preg_split('/\s+/', trim($entry)) ?: [])[0] ?? '';
                        if (self::isBlockedUri($url)) {
                            $node->removeAttribute($attr);
                            break;
                        }
                    }
                } elseif (self::isBlockedUri($value)) {
                    $node->removeAttribute($attr);
                }
            }
        }

        // --- 6. Prevent DOM clobbering by removing dangerous id/name attributes ---
        foreach (self::$blockedNames as $blocked) {
            // Remove id attributes
            $nodesWithId = $xpath->query("//*[@id='$blocked']");
            if( $nodesWithId !== false ) {
                foreach ($nodesWithId as $node) {
                    if( $node instanceof \DOMElement ) {
                        $node->removeAttribute('id');
                    }
                }
            }

            // Remove name attributes
            $nodesWithName = $xpath->query("//*[@name='$blocked']");
            if( $nodesWithName !== false ) {
                foreach ($nodesWithName as $node) {
                    if( $node instanceof \DOMElement ) {
                        $node->removeAttribute('name');
                    }
                }
            }
        }

        // --- 7. Add rel="noopener noreferrer" to target="_blank" links ---
        $blankLinks = $xpath->query('//a[@target="_blank"]');
        if( $blankLinks !== false ) {
            foreach ($blankLinks as $node) {
                if( $node instanceof \DOMElement ) {
                    $node->setAttribute('rel', 'noopener noreferrer');
                }
            }
        }

        // Return sanitized HTML without XML declaration
        $html = $doc->saveHTML();
        if( $html === false ) {
            return '';
        }
        $pos = strpos($html, '?>');
        return $pos !== false ? substr($html, $pos + 2) : $html;
    }


    /**
     * @param list<string> $uris
     */
    private static function filterByUri( \DOMXPath $xpath, string $tag, array $uris ) : void
    {
        $uriAttr = self::$tagUriAttr[$tag] ?? null;
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

            if( !$val || !self::isAllowedUri( $val, $uris ) || self::isBlockedUri( $val ) )
            {
                $node->parentNode?->removeChild( $node );
                continue;
            }

            // Strip attributes and enforce sandbox only for embedding tags
            if( isset( self::$safeAttrs[$tag] ) )
            {
                $safe = self::$safeAttrs[$tag];
                $attrsToRemove = [];

                foreach( $node->attributes as $attr ) {
                    if( !in_array( $attr->name, $safe, true ) ) {
                        $attrsToRemove[] = $attr->name;
                    }
                }

                foreach( $attrsToRemove as $name ) {
                    $node->removeAttribute( $name );
                }

                if( in_array( $tag, ['iframe', 'frame'], true ) ) {
                    $node->setAttribute( 'sandbox', 'allow-scripts allow-same-origin allow-popups' );
                }
            }
        }
    }


    /**
     * @param list<string> $uris
     */
    private static function isAllowedUri( string $src, array $uris ) : bool
    {
        $src = strtolower( $src );

        foreach( $uris as $uri )
        {
            $uri = strtolower( $uri );

            if( str_starts_with( $src, $uri ) ) {
                return true;
            }
        }

        return false;
    }


    private static function isBlockedUri( string $value ) : bool
    {
        if (!preg_match('/^\s*([a-zA-Z][a-zA-Z0-9+.-]*)\s*:/i', $value, $matches)) {
            return false;
        }

        $scheme = strtolower($matches[1]);

        if (in_array($scheme, self::$blockedSchemes, true)) {
            return true;
        }

        if ($scheme === 'data') {
            return !preg_match('#^data:\s*([\w/+-]+)\s*[;,]#i', $value, $mimeMatch)
                || !in_array(strtolower($mimeMatch[1]), self::$allowedDataMimes, true);
        }

        return false;
    }
}
