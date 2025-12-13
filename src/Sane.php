<?php

namespace Aimeos\Sanitizer;


class Sane
{
    // Unsafe elements to remove completely
    private static array $removeElements = ['embed', 'frame', 'iframe', 'object', 'script', 'svg'];

    // Event handler attributes to remove
    private static array $removeAttributes = [
        "onafterprint","onauxclick","onbeforeinput","onbeforematch","onbeforeprint","onbeforeunload",
        "onbeforetoggle","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose",
        "oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick",
        "ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop",
        "ondurationchange","onemptied","onended","onerror","onfocus","onformdata","onhashchange",
        "oninput","oninvalid","onkeydown","onkeypress","onkeyup","onlanguagechange","onload",
        "onloadeddata","onloadedmetadata","onloadstart","onmessage","onmessageerror","onmousedown",
        "onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onoffline",
        "ononline","onpagehide","onpagereveal","onpageshow","onpageswap","onpaste","onpause","onplay",
        "onplaying","onpopstate","onprogress","onratechange","onreset","onresize","onrejectionhandled",
        "onscroll","onscrollend","onsecuritypolicyviolation","onseeked","onseeking","onselect",
        "onslotchange","onstalled","onstorage","onsubmit","onsuspend","ontimeupdate","ontoggle",
        "onunhandledrejection","onunload","onvolumechange","onwaiting","onwheel"
    ];

    // Attributes that may contain URIs
    private static array $uriAttributes = [
        'href', 'src', 'xlink:href', 'formaction', 'action', 'background'
    ];

    // Disallowed URI schemes
    private static array $blockedSchemes = ['javascript', 'data', 'vbscript', 'file', 'filesystem', 'blob'];

    private static array $blockedNames = [
        'location', 'window', 'document', 'frames', 'self', 'parent', 'top',
        'opener', 'alert', 'confirm', 'prompt', 'navigator', 'history', 'event',
        'console', 'frames', 'length', 'content', 'forms', 'images', 'anchors'
    ];

    public static function html( string $input ) : string
    {
        $doc = new \DOMDocument();

        libxml_use_internal_errors(true);
        $doc->loadHTML('<?xml encoding="UTF-8">' . $input, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_clear_errors();

        $xpath = new \DOMXPath($doc);

        // --- 1. Remove all unsafe elements ---
        foreach (self::$removeElements as $tag) {
            $nodes = $xpath->query("//{$tag}");
            foreach ($nodes as $node) {
                $node->parentNode->removeChild($node);
            }
        }

        // --- 2. Remove unsafe event handler attributes ---
        foreach (self::$removeAttributes as $attr) {
            $nodesWithAttr = $xpath->query("//*[@$attr]");
            foreach ($nodesWithAttr as $node) {
                $node->removeAttribute($attr);
            }
        }

        // --- 3. Remove all style attributes ---
        $styleNodes = $xpath->query('//*[@style]');
        foreach ($styleNodes as $node) {
            $node->removeAttribute('style');
        }

        // --- 4. Remove attributes with disallowed URI schemes ---
        foreach (self::$uriAttributes as $attr) {
            $nodesWithAttr = $xpath->query("//*[@$attr]");
            foreach ($nodesWithAttr as $node) {
                $value = html_entity_decode($node->getAttribute($attr), ENT_QUOTES | ENT_HTML5);
                $value = trim($value);

                if (preg_match('/^\s*([a-zA-Z][a-zA-Z0-9+.-]*)\s*:/i', $value, $matches)) {
                    $scheme = strtolower($matches[1]);
                    if (in_array($scheme, self::$blockedSchemes, true)) {
                        $node->removeAttribute($attr);
                    }
                }
            }
        }

        // --- 5. Prevent DOM clobbering by removing dangerous id/name attributes ---
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

        // Return sanitized HTML without XML declaration
        return preg_replace('/^<\?xml.*?\?>/', '', $doc->saveHTML());
    }
}
