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

    // Resource limits for hostile input: deeply nested markup makes the HTML
    // parser run in roughly O(depth^2), and very large input is costly to
    // process. Input exceeding either limit is rejected (returns "").
    private const MAX_LENGTH = 4194304;   // 4 MiB
    private const MAX_DEPTH = 256;
    private const MAX_ELEMENTS = 50000;


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
        // Reject hostile input before the parser and pipeline run on it.
        if( strlen( $input ) > self::MAX_LENGTH || self::exceedsLimits( $input ) ) {
            return '';
        }

        // Parse with the HTML5 algorithm (matching browsers) so the
        // parse → sanitize → serialize → browser-reparse cycle stays
        // consistent and can't be exploited via parser-differential mutation
        // XSS the way the libxml HTML4 parser could.
        $html5 = new \Masterminds\HTML5(['disable_html_ns' => true]);
        $doc = $html5->loadHTML('<!DOCTYPE html><html><body>' . $input . '</body></html>');

        $xpath = new \DOMXPath($doc);

        // --- Opt allowed elements back in (hardened); collect the rest for removal ---
        $removeSet = [];
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
            $removeSet[$tag] = true;
        }
        // --- Collapse any kept <noscript> to its text content. Browsers with
        //     scripting enabled parse noscript content as raw text, so a stray
        //     </noscript> in an attribute would re-open parsing in the browser
        //     and free the following markup. Only reachable when noscript is
        //     allowed (otherwise it was collected for removal above). ---
        if( isset( $allow['noscript'] ) ) {
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
        }

        // --- Single pass over every node: remove comments, unsafe elements and
        //     script-bearing SVG elements, then on surviving elements strip
        //     event-handler/style/dangerous-URI and clobbering id/name attributes
        //     and add rel="noopener noreferrer" to target="_blank" links. ---
        $animSet = array_flip( self::$unsafeSvgElements );
        $blockedSet = array_flip( self::$blockedNames );
        $uriSet = array_flip( self::$uriAttributes );
        $nodes = $xpath->query('//comment() | //*');
        if( $nodes !== false ) {
            foreach ($nodes as $node) {
                if( $node instanceof \DOMComment ) {
                    $node->parentNode?->removeChild($node);
                    continue;
                }
                if( !$node instanceof \DOMElement ) {
                    continue;
                }
                $tag = $node->nodeName;
                if( isset( $removeSet[$tag] ) || isset( $animSet[strtolower($tag)] ) ) {
                    $node->parentNode?->removeChild($node);
                    continue;
                }

                $remove = [];
                $blankTarget = false;
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
                    if( $name === 'target' && $attribute->value === '_blank' ) {
                        $blankTarget = true;
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
                    $value = trim($attribute->value);

                    if ($attribute->localName === 'srcset') {
                        foreach (preg_split('/\s*,\s*/', $value) ?: [] as $entry) {
                            $url = (preg_split('/\s+/', trim($entry)) ?: [])[0] ?? '';
                            if (self::isBlockedUri($url)) {
                                $remove[] = $attribute;
                                break;
                            }
                        }
                    } elseif (self::isBlockedUri($value)) {
                        $remove[] = $attribute;
                    }
                }
                foreach ($remove as $attribute) {
                    $node->removeAttributeNode($attribute);
                }

                if( $blankTarget && ($tag === 'a' || $tag === 'area' || $tag === 'form') ) {
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

        // --- Neutralize <meta http-equiv="refresh"> redirects to blocked schemes.
        //     Only reachable when meta is allowed. ---
        if( isset( $allow['meta'] ) ) {
            $metaNodes = $xpath->query('//meta[@content]');
            if( $metaNodes !== false ) {
                foreach ($metaNodes as $node) {
                    if( !$node instanceof \DOMElement ) {
                        continue;
                    }
                    // Strip TAB/CR/LF first so an embedded control char can't hide
                    // the scheme from the URL extraction below (browsers strip them).
                    $content = (string) preg_replace('/[\x09\x0a\x0d]/', '', $node->getAttribute('content'));
                    // The redirect URL follows the time and a separator (";", "," or
                    // whitespace), with an optional "url=" prefix — handle every form.
                    if( strcasecmp($node->getAttribute('http-equiv'), 'refresh') === 0
                        && preg_match('/^\s*[\d.]*\s*[;,]?\s*(?:url\s*=\s*)?["\']?\s*([^"\'\s>]+)/i', $content, $m)
                        && self::isBlockedUri($m[1])
                    ) {
                        $node->removeAttribute('content');
                    }
                }
            }
        }

        // --- Drop inline scripts; an allowed <script> is only kept when it loads
        //     from an external src that survived the scheme check. Only reachable
        //     when script is allowed. ---
        if( isset( $allow['script'] ) ) {
            $scriptNodes = $xpath->query('//script');
            if( $scriptNodes !== false ) {
                foreach ($scriptNodes as $node) {
                    if( $node instanceof \DOMElement && trim($node->getAttribute('src')) === '' ) {
                        $node->parentNode?->removeChild($node);
                    }
                }
            }
        }

        // --- Unwrap structural document elements (<html>/<head>/<body>/<title>/
        //     <frameset>) the parser may have nested inside the wrapper body, so
        //     they don't leak into the fragment output (and can't inject
        //     attributes into a host page's body/html if the output is inlined). ---
        // (SVG/MathML <title> is a real child element there, so exclude it.)
        $structural = $xpath->query('//body//html | //body//head | //body//body | //body//frameset'
            . ' | //body//title[not(ancestor::svg) and not(ancestor::math)]');
        if( $structural !== false ) {
            foreach ($structural as $node) {
                if( !$node instanceof \DOMElement || $node->parentNode === null ) {
                    continue;
                }
                while( $node->firstChild !== null ) {
                    $node->parentNode->insertBefore( $node->firstChild, $node );
                }
                $node->parentNode->removeChild( $node );
            }
        }

        // --- Return the sanitized content of the wrapper body. Its own attributes
        //     are never part of the output and are cleared so the wrapper-tag strip
        //     stays robust even if the parser merged input <body> attributes onto
        //     it; serializing once is much faster than a saveHTML() call per child
        //     when there are many top-level nodes. ---
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
        $html = (string) preg_replace('#^\s*<body[^>]*>#i', '', $html5->saveHTML( $body ));
        return (string) preg_replace('#</body>\s*$#i', '', $html);
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
            // Normalize like a browser (strip TAB/CR/LF and leading control
            // chars, treat backslashes as slashes) so "\\evil", "/\evil" and
            // "ht&#9;tps://evil" can't slip past the cross-origin test below.
            $href = str_replace('\\', '/', (string) preg_replace('/[\x09\x0a\x0d]/', '', $node->getAttribute('href')));
            $href = (string) preg_replace('/^[\x00-\x20]+/', '', $href);

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
        $boundary = ['/', '?', '#'];

        foreach( $uris as $uri )
        {
            $uri = strtolower( trim( $uri ) );

            // Skip empty prefixes — str_starts_with('', ...) would allow anything.
            if( $uri === '' || !str_starts_with( $src, $uri ) ) {
                continue;
            }

            // A protocol-relative ("//host") candidate is cross-origin; only
            // allow it when the prefix is itself protocol-relative, not a bare
            // path prefix like "/".
            if( str_starts_with( $src, '//' ) && !str_starts_with( $uri, '//' ) ) {
                continue;
            }

            // Require the match to end at a path/query/fragment boundary so a
            // host-level prefix like "https://site.com" cannot be extended to
            // "https://site.com.evil.com" or "https://site.com@evil.com".
            $next = $src[strlen( $uri )] ?? '';

            if( in_array( substr( $uri, -1 ), $boundary, true )
                || $next === '' || in_array( $next, $boundary, true )
            ) {
                return true;
            }
        }

        return false;
    }


    /**
     * Cheap linear pre-scan reporting whether the markup exceeds the nesting
     * depth (self::MAX_DEPTH) or element-count (self::MAX_ELEMENTS) limits, used
     * to reject pathological input before the parser and the per-element
     * pipeline run on it. It mirrors the parser closely enough not to be gamed
     * downward on depth: a close tag only pops a matching open (so bogus "</z>"
     * can't keep the depth low), a self-closing slash counts as nesting in HTML
     * ("<div/>" nests) but not in SVG/MathML, and the common implied end tags
     * are applied so omitted optional close tags on legitimate lists, tables and
     * paragraphs don't pile up.
     */
    private static function exceedsLimits( string $input ) : bool
    {
        static $void = ['area' => 1, 'base' => 1, 'br' => 1, 'col' => 1, 'embed' => 1,
            'hr' => 1, 'img' => 1, 'input' => 1, 'keygen' => 1, 'link' => 1, 'meta' => 1,
            'param' => 1, 'source' => 1, 'track' => 1, 'wbr' => 1];
        // Elements whose content is HTML even inside SVG/MathML (self-close not honored there)
        static $htmlContext = ['foreignobject' => 1, 'desc' => 1, 'title' => 1,
            'mi' => 1, 'mo' => 1, 'mn' => 1, 'ms' => 1, 'mtext' => 1, 'annotation-xml' => 1];
        // A start tag (key) implies the end of these currently-open elements (value set)
        static $implied = [
            'li' => ['li' => 1],
            'dt' => ['dt' => 1, 'dd' => 1], 'dd' => ['dt' => 1, 'dd' => 1],
            'option' => ['option' => 1], 'optgroup' => ['option' => 1, 'optgroup' => 1],
            'td' => ['td' => 1, 'th' => 1], 'th' => ['td' => 1, 'th' => 1],
            'tr' => ['tr' => 1, 'td' => 1, 'th' => 1],
            'tbody' => ['tr' => 1, 'td' => 1, 'th' => 1, 'tbody' => 1, 'thead' => 1, 'tfoot' => 1],
            'thead' => ['tr' => 1, 'td' => 1, 'th' => 1, 'tbody' => 1, 'thead' => 1, 'tfoot' => 1],
            'tfoot' => ['tr' => 1, 'td' => 1, 'th' => 1, 'tbody' => 1, 'thead' => 1, 'tfoot' => 1],
        ];
        // Block-level start tags additionally close an open <p>
        static $blocks = ['address' => 1, 'article' => 1, 'aside' => 1, 'blockquote' => 1,
            'details' => 1, 'div' => 1, 'dl' => 1, 'fieldset' => 1, 'figcaption' => 1,
            'figure' => 1, 'footer' => 1, 'form' => 1, 'h1' => 1, 'h2' => 1, 'h3' => 1,
            'h4' => 1, 'h5' => 1, 'h6' => 1, 'header' => 1, 'hgroup' => 1, 'main' => 1,
            'menu' => 1, 'nav' => 1, 'ol' => 1, 'p' => 1, 'pre' => 1, 'section' => 1,
            'table' => 1, 'ul' => 1];

        $stack = [];        // open element names
        $foreign = [];      // parallel: whether each open element holds SVG/MathML content
        $inForeign = false;
        $total = 0;         // total start tags seen (≈ DOM nodes the pipeline visits)
        $len = strlen( $input );
        $offset = 0;

        while( ($pos = strpos( $input, '<', $offset )) !== false )
        {
            $offset = $pos + 1;
            $ch = $input[$offset] ?? '';

            if( $ch === '/' )   // end tag — pop down to the matching open, if any
            {
                $name = self::tagName( $input, $offset + 1, $len );
                for( $i = count( $stack ) - 1; $i >= 0; $i-- ) {
                    if( $stack[$i] === $name ) {
                        array_splice( $stack, $i );
                        array_splice( $foreign, $i );
                        break;
                    }
                }
                $inForeign = $foreign === [] ? false : $foreign[count( $foreign ) - 1];
                continue;
            }

            if( !ctype_alpha( $ch ) ) {
                continue;       // comment, declaration, processing instruction or stray "<"
            }

            if( ++$total > self::MAX_ELEMENTS ) {
                return true;
            }

            $name = self::tagName( $input, $offset, $len );
            $gt = strpos( $input, '>', $offset );
            $selfClosing = $gt !== false && $input[$gt - 1] === '/';

            // Void elements never nest; a self-closing slash only ends the tag
            // in SVG/MathML content, where "<circle/>" is a leaf.
            if( isset( $void[$name] ) || ( $selfClosing && ( $inForeign || $name === 'svg' || $name === 'math' ) ) ) {
                continue;
            }

            // Apply implied end tags so omitted optional close tags don't pile up.
            while( $stack !== [] ) {
                $top = $stack[count( $stack ) - 1];
                if( isset( $implied[$name][$top] ) || ( $top === 'p' && isset( $blocks[$name] ) ) ) {
                    array_pop( $stack );
                    array_pop( $foreign );
                } else {
                    break;
                }
            }
            $inForeign = $foreign === [] ? false : $foreign[count( $foreign ) - 1];

            $stack[] = $name;
            $foreign[] = $inForeign = $name === 'svg' || $name === 'math'
                ? true
                : ( isset( $htmlContext[$name] ) ? false : $inForeign );

            if( count( $stack ) > self::MAX_DEPTH ) {
                return true;
            }
        }

        return false;
    }


    private static function tagName( string $input, int $start, int $len ) : string
    {
        $end = $start;
        while( $end < $len && (ctype_alnum( $input[$end] ) || $input[$end] === '-') ) {
            $end++;
        }
        return strtolower( substr( $input, $start, $end - $start ) );
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
