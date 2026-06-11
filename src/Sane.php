<?php

namespace Aimeos\Sanitizer;


class Sane
{
    // Unsafe elements to remove completely. Includes raw-text elements
    // (plaintext, xmp, noembed, noframes) whose content browsers parse as text
    // but the libxml DOM does not, to avoid parser-differential surprises.
    /** @var list<string> */
    private static array $removeElements = ['applet', 'base', 'embed', 'form', 'frame', 'iframe', 'link', 'math', 'meta', 'noembed', 'noframes', 'noscript', 'object', 'plaintext', 'portal', 'script', 'style', 'svg', 'template', 'xmp'];

    // SVG elements that carry or set script (SMIL animation, XML-Events handler);
    // always removed, even inside an allowed <svg>. Matched case-insensitively.
    /** @var list<string> */
    private static array $unsafeSvgElements = ['animate', 'animatemotion', 'animatetransform', 'animatecolor', 'set', 'handler'];

    // Attributes that may contain URIs
    /** @var list<string> */
    private static array $uriAttributes = [
        'href', 'src', 'xlink:href', 'formaction', 'action', 'background', 'poster', 'ping', 'srcset', 'data'
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

    // Permissions-Policy features allowed in an iframe "allow" attribute; covers
    // common media embeds while dropping powerful ones (camera, microphone,
    // geolocation, display-capture, usb, ...).
    /** @var list<string> */
    private static array $safeAllowFeatures = [
        'accelerometer', 'autoplay', 'clipboard-write', 'encrypted-media',
        'fullscreen', 'gyroscope', 'picture-in-picture', 'web-share'
    ];

    // Best-effort DOM-clobbering denylist: id/name values that would shadow a
    // window/document/form property. Not exhaustive — see SANITIZE_DOM-style
    // checks for full coverage.
    /** @var list<string> */
    private static array $blockedNames = [
        'location', 'window', 'document', 'frames', 'self', 'parent', 'top',
        'opener', 'alert', 'confirm', 'prompt', 'navigator', 'history', 'event',
        'console', 'length', 'content', 'forms', 'images', 'anchors', 'links',
        'scripts', 'embeds', 'plugins', 'applets', 'all', 'cookie', 'domain',
        'referrer', 'defaultView', 'documentElement', 'body', 'head',
        'getElementById', 'getElementsByName', 'createElement', 'write',
        'writeln', 'querySelector', 'querySelectorAll'
    ];


    /**
     * Sanitizes the HTML input, removing potentially dangerous content.
     *
     * The $allow map opts specific blocked elements back in, keyed by tag name:
     * - true keeps the element regardless of its URL. Event handlers, "style"
     *   attributes and dangerous-scheme URLs are still stripped, and inline
     *   <script> is dropped (only scripts loading from an external src are
     *   kept). Other inline content such as <style> CSS is kept verbatim, so
     *   only pass true for tags you fully trust.
     * - list<string> keeps the element only when its URL starts with one of the
     *   given prefixes; embedding tags are additionally reduced to a safe
     *   attribute allow-list and sandboxed.
     *
     * @param array<string, bool|list<string>> $allow
     */
    public static function html( string $input, array $allow = [] ) : string
    {
        // Parse with the HTML5 algorithm (matching browsers) so the
        // parse → sanitize → serialize → browser-reparse cycle stays
        // consistent and can't be exploited via parser-differential mutation
        // XSS the way the libxml HTML4 parser could.
        $html5 = new \Masterminds\HTML5(['disable_html_ns' => true]);
        $doc = $html5->loadHTML('<!DOCTYPE html><html><body>' . $input . '</body></html>');

        $xpath = new \DOMXPath($doc);

        // --- 1. Remove all unsafe elements (skip those with allowed URIs) ---
        foreach (self::$removeElements as $tag) {
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

        // --- 1b. Remove script-bearing SVG elements (even inside an allowed svg) ---
        $lname = "translate(local-name(),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')";
        $conds = array_map( fn( $el ) => "{$lname}='{$el}'", self::$unsafeSvgElements );
        $animNodes = $xpath->query('//*[' . implode( ' or ', $conds ) . ']');
        if( $animNodes !== false ) {
            foreach ($animNodes as $node) {
                if( $node instanceof \DOMNode ) {
                    $node->parentNode?->removeChild($node);
                }
            }
        }

        // --- 1c. Collapse any kept <noscript> to its text content. Browsers with
        //         scripting enabled parse noscript content as raw text, but the
        //         parser here builds a DOM, so a stray </noscript> in an attribute
        //         would re-open parsing in the browser and free following markup. ---
        $noscriptNodes = $xpath->query('//noscript');
        if( $noscriptNodes !== false ) {
            foreach ($noscriptNodes as $node) {
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
        $uriNodes = $xpath->query('//*');
        if( $uriNodes !== false ) {
            foreach ($uriNodes as $node) {
                if( !$node instanceof \DOMElement ) {
                    continue;
                }
                $blocked = [];
                foreach ($node->attributes as $attribute) {
                    // Match the full and local name so namespaced URI attributes
                    // such as xlink:href (local name "href") are checked too.
                    if( !in_array($attribute->name, self::$uriAttributes, true)
                        && !in_array($attribute->localName, self::$uriAttributes, true)
                    ) {
                        continue;
                    }
                    // The attribute value is already entity-decoded to what the
                    // browser sees, so it is checked as-is.
                    $value = trim($attribute->value);

                    if ($attribute->localName === 'srcset') {
                        foreach (preg_split('/\s*,\s*/', $value) ?: [] as $entry) {
                            $url = (preg_split('/\s+/', trim($entry)) ?: [])[0] ?? '';
                            if (self::isBlockedUri($url)) {
                                $blocked[] = $attribute;
                                break;
                            }
                        }
                    } elseif (self::isBlockedUri($value)) {
                        $blocked[] = $attribute;
                    }
                }
                foreach ($blocked as $attribute) {
                    $node->removeAttributeNode($attribute);
                }
            }
        }

        // --- 5b. Neutralize <meta http-equiv="refresh"> redirects to blocked schemes ---
        $metaNodes = $xpath->query('//meta[@content]');
        if( $metaNodes !== false ) {
            foreach ($metaNodes as $node) {
                if( !$node instanceof \DOMElement ) {
                    continue;
                }
                // Strip TAB/CR/LF first so an embedded control char can't hide
                // the scheme from the URL extraction below (browsers strip them).
                $content = (string) preg_replace('/[\x09\x0a\x0d]/', '', $node->getAttribute('content'));
                if( strcasecmp($node->getAttribute('http-equiv'), 'refresh') === 0
                    && preg_match('/url\s*=\s*["\']?\s*([^"\'\s>]+)/i', $content, $m)
                    && self::isBlockedUri($m[1])
                ) {
                    $node->removeAttribute('content');
                }
            }
        }

        // --- 5c. Drop inline scripts; an allowed <script> is only kept when it
        //         loads from an external src that survived the scheme check ---
        $scriptNodes = $xpath->query('//script');
        if( $scriptNodes !== false ) {
            foreach ($scriptNodes as $node) {
                if( $node instanceof \DOMElement && trim($node->getAttribute('src')) === '' ) {
                    $node->parentNode?->removeChild($node);
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
        $blankLinks = $xpath->query('//a[@target="_blank"] | //area[@target="_blank"] | //form[@target="_blank"]');
        if( $blankLinks !== false ) {
            foreach ($blankLinks as $node) {
                if( $node instanceof \DOMElement ) {
                    $rel = preg_split('/\s+/', trim($node->getAttribute('rel')), -1, PREG_SPLIT_NO_EMPTY) ?: [];
                    foreach (['noopener', 'noreferrer'] as $token) {
                        if( !in_array($token, $rel, true) ) {
                            $rel[] = $token;
                        }
                    }
                    $node->setAttribute('rel', implode(' ', $rel));
                }
            }
        }

        // Return the sanitized content of the wrapper body only.
        $body = $doc->getElementsByTagName('body')->item(0);
        $html = '';
        if( $body instanceof \DOMElement ) {
            foreach( $body->childNodes as $child ) {
                $html .= $html5->saveHTML( $child );
            }
        }
        return $html;
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
            if( !$node instanceof \DOMElement ) {
                continue;
            }
            $href = trim( $node->getAttribute('href') );
            if( str_starts_with($href, '//') || preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*:#', $href) ) {
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
        if( !isset( self::$safeAttrs[$tag] ) ) {
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
        if( !isset( self::$safeAttrs[$tag] ) ) {
            return;
        }

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

        // Restrict the iframe Permissions-Policy "allow" attribute to safe
        // features so an allowed embed can't request e.g. camera or microphone.
        if( $tag === 'iframe' && $node->hasAttribute( 'allow' ) ) {
            $kept = [];
            foreach( explode( ';', $node->getAttribute( 'allow' ) ) as $directive ) {
                $directive = trim( $directive );
                $feature = strtolower( (preg_split( '/\s+/', $directive ) ?: [''])[0] );
                if( $directive !== '' && in_array( $feature, self::$safeAllowFeatures, true ) ) {
                    $kept[] = $directive;
                }
            }
            $kept ? $node->setAttribute( 'allow', implode( '; ', $kept ) ) : $node->removeAttribute( 'allow' );
        }

        if( in_array( $tag, ['iframe', 'frame'], true ) ) {
            // No allow-same-origin: together with allow-scripts it lets
            // same-origin framed content remove its own sandbox and escape.
            // (Browsers ignore the attribute on <frame>, which cannot be
            // sandboxed — avoid allowing <frame> for untrusted origins.)
            $node->setAttribute( 'sandbox', 'allow-scripts allow-popups' );
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
        // Browsers strip TAB, LF and CR from anywhere in a URL and ignore
        // leading control characters/whitespace before resolving the scheme.
        // Normalize the same way so payloads like "java&#9;script:" or a
        // leading "\x01javascript:" cannot slip past the scheme detection.
        $value = (string) preg_replace('/[\x09\x0a\x0d]+/', '', $value);
        $value = (string) preg_replace('/^[\x00-\x20]+/', '', $value);

        if (!preg_match('/^([a-zA-Z][a-zA-Z0-9+.-]*):/', $value, $matches)) {
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
