<?php

namespace Aimeos\Sanitizer;


class Sane
{
    // Unsafe elements to remove completely
    private static array $removeElements = ['base', 'embed', 'form', 'frame', 'iframe', 'link', 'math', 'meta', 'noscript', 'object', 'script', 'style', 'svg', 'template'];

    // Attributes that may contain URIs
    private static array $uriAttributes = [
        'href', 'src', 'xlink:href', 'formaction', 'action', 'background', 'poster', 'ping', 'srcset'
    ];

    // Disallowed URI schemes
    private static array $blockedSchemes = ['javascript', 'vbscript', 'file', 'filesystem', 'blob'];

    // Allowed MIME types for data: URIs
    private static array $allowedDataMimes = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

    private static array $blockedNames = [
        'location', 'window', 'document', 'frames', 'self', 'parent', 'top',
        'opener', 'alert', 'confirm', 'prompt', 'navigator', 'history', 'event',
        'console', 'frames', 'length', 'content', 'forms', 'images', 'anchors'
    ];


    public static function html( string $input ) : string
    {
        $doc = new \DOMDocument();

        libxml_use_internal_errors(true);
        $doc->loadHTML('<?xml version="1.0" encoding="utf-8"?>' . $input, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        $doc->normalizeDocument();
        libxml_clear_errors();

        $xpath = new \DOMXPath($doc);

        // --- 1. Remove all unsafe elements ---
        foreach (self::$removeElements as $tag) {
            $nodes = $xpath->query("//{$tag}");
            foreach ($nodes as $node) {
                $node->parentNode->removeChild($node);
            }
        }

        // --- 2. Remove HTML comments ---
        foreach ($xpath->query('//comment()') as $comment) {
            $comment->parentNode->removeChild($comment);
        }

        // --- 3. Remove all on* event handler attributes ---
        foreach ($xpath->query('//*') as $node) {
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

        // --- 4. Remove all style attributes ---
        $styleNodes = $xpath->query('//*[@style]');
        foreach ($styleNodes as $node) {
            $node->removeAttribute('style');
        }

        // --- 5. Remove attributes with disallowed URI schemes ---
        foreach (self::$uriAttributes as $attr) {
            $nodesWithAttr = $xpath->query('//*[@*[local-name()="' . $attr . '"]]');
            foreach ($nodesWithAttr as $node) {
                $value = html_entity_decode($node->getAttribute($attr), ENT_QUOTES | ENT_HTML5);
                $value = trim($value);

                if ($attr === 'srcset') {
                    foreach (preg_split('/\s*,\s*/', $value) as $entry) {
                        $url = preg_split('/\s+/', trim($entry))[0] ?? '';
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
            foreach ($nodesWithId as $node) {
                $node->removeAttribute('id');
            }

            // Remove name attributes
            $nodesWithName = $xpath->query("//*[@name='$blocked']");
            foreach ($nodesWithName as $node) {
                $node->removeAttribute('name');
            }
        }

        // --- 7. Add rel="noopener noreferrer" to target="_blank" links ---
        foreach ($xpath->query('//a[@target="_blank"]') as $node) {
            $node->setAttribute('rel', 'noopener noreferrer');
        }

        // Return sanitized HTML without XML declaration
        $html = $doc->saveHTML();
        $pos = strpos($html, '?>');
        return $pos !== false ? substr($html, $pos + 2) : $html;
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
