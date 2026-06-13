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
        'href', 'src', 'xlink:href', 'formaction', 'action', 'background', 'poster', 'ping', 'srcset', 'data',
        'cite', 'longdesc'
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
    private const MAX_STRAY = 16384;      // stray "<" that hit the parser's O(n^2) path
    private const MAX_ATTR_WORK = 16000000;   // bounds the parser's ~O(attrs^2)-per-element cost
    private const MAX_SWALLOW = 2048;     // malformed "<" consumed inside tags (drives O(n^2) reconstruction)
    private const MAX_MISMATCH = 2048;    // unmatched end tags (drive O(n^2) foster-parenting/adoption work)


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
        // Reject hostile input before the parser and pipeline run on it. The cap
        // also keeps the (Masterminds-specific) O(n^2) parser paths bounded; on the
        // native path below it bounds the per-element pipeline and attribute cost.
        if( strlen( $input ) > self::MAX_LENGTH || self::exceedsLimits( $input ) ) {
            return '';
        }

        // PHP 8.4+: parse with the native, spec-compliant, O(n) HTML5 parser
        // (lexbor) and serialize with it too, so even crafted misnested tag soup
        // can't drive the parser into superlinear time. Falls back to the
        // Masterminds path on PHP 8.0-8.3.
        if( class_exists( '\Dom\HTMLDocument' ) ) {
            return self::htmlNative( $input, $allow );
        }

        return self::htmlLegacy( $input, $allow );
    }


    /**
     * Masterminds (pure-PHP HTML5) sanitization path for PHP 8.0-8.3, where the
     * native parser is unavailable. Identical behaviour to the native path, modulo
     * cosmetic serialization differences.
     *
     * @param array<string, bool|list<string>> $allow
     */
    private static function htmlLegacy( string $input, array $allow ) : string
    {
        // Parse with the HTML5 algorithm (matching browsers) so the
        // parse → sanitize → serialize → browser-reparse cycle stays
        // consistent and can't be exploited via parser-differential mutation
        // XSS the way the libxml HTML4 parser could.
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
     * Native (lexbor) sanitization path for PHP 8.4+. Mirrors htmlLegacy() against
     * the spec-compliant \Dom API: elements are matched by lower-case local name
     * (HTML names are upper-cased and foreign content carries real namespaces here)
     * and serialization round-trips faithfully, so the parser-differential passes
     * still run but find nothing to fix. The one behavioural difference is an
     * allowed <template>: lexbor sequesters its children in an unreachable content
     * fragment, so this path drops that content (nativeStripTemplateContent) rather
     * than sanitizing it in place — safe, but emptier than the legacy output. These
     * methods only execute when \Dom\HTMLDocument exists, so their \Dom\* type
     * hints are never resolved on PHP 8.0-8.3.
     *
     * @param array<string, bool|list<string>> $allow
     */
    private static function htmlNative( string $input, array $allow ) : string
    {
        $doc = \Dom\HTMLDocument::createFromString(
            '<!DOCTYPE html><html><body>' . $input . '</body></html>', LIBXML_NOERROR
        );
        $xpath = new \Dom\XPath( $doc );

        $removeSet = self::nativeApplyAllowList( $xpath, $allow );

        if( isset( $allow['noscript'] ) ) {
            self::nativeCollapseNoscript( $xpath, $doc );
        }
        if( stripos( $input, '<![cdata[' ) !== false ) {
            self::nativeNeutralizeCdata( $xpath, $doc );
        }

        self::nativeSanitizeNodes( $xpath, $doc, $removeSet );

        if( isset( $allow['template'] ) ) {
            self::nativeStripTemplateContent( $xpath );
        }
        if( isset( $allow['style'] ) || isset( $allow['script'] ) ) {
            self::nativeDropRawTextBreakouts( $xpath );
        }
        if( isset( $allow['meta'] ) ) {
            self::nativeCheckMetaRefresh( $xpath );
        }
        if( isset( $allow['script'] ) ) {
            self::nativeDropInlineScripts( $xpath );
        }
        self::nativeUnwrapStructural( $xpath );

        return self::nativeSerializeBody( $doc );
    }


    /**
     * @param array<string, bool|list<string>> $allow
     * @return array<string, true>
     */
    private static function nativeApplyAllowList( \Dom\XPath $xpath, array $allow ) : array
    {
        $removeSet = [];
        foreach (self::$removeElements as $tag) {
            if( isset( $allow[$tag] ) ) {
                if( $allow[$tag] === true ) {
                    self::nativeHardenAllowed( $xpath, $tag );
                    if( $tag === 'base' ) {
                        self::nativeRestrictBaseHref( $xpath );
                    }
                    continue;
                }
                self::nativeFilterByUri( $xpath, $tag, array_values( array_filter( (array) $allow[$tag], 'is_string' ) ) );
                continue;
            }
            $removeSet[$tag] = true;
        }
        return $removeSet;
    }


    private static function nativeCollapseNoscript( \Dom\XPath $xpath, \Dom\HTMLDocument $doc ) : void
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
     * by nativeRemoveComments) and CDATA in foreign content as escaped text, so it
     * never emits a \Dom\CdataSection here — unlike the libxml DOM the legacy path
     * builds. Kept as a guard in case a future build does, mirroring the legacy pass.
     */
    private static function nativeNeutralizeCdata( \Dom\XPath $xpath, \Dom\HTMLDocument $doc ) : void
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
    private static function nativeSanitizeNodes( \Dom\XPath $xpath, \Dom\HTMLDocument $doc, array $removeSet ) : void
    {
        $animSet = array_flip( self::$unsafeSvgElements );
        $blockedSet = array_flip( self::$blockedNames );
        $uriSet = array_flip( self::$uriAttributes );

        if( $doc->documentElement !== null ) {
            self::nativeRemoveComments( $doc->documentElement );
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
                if (self::uriValueBlocked($local, trim($attribute->value))) {
                    $remove[] = $attribute;
                }
            }
            foreach ($remove as $attribute) {
                $node->removeAttributeNode($attribute);
            }

            if( $newWindow && ($tag === 'a' || $tag === 'area' || $tag === 'form') ) {
                $node->setAttribute('rel', self::mergeRel($node->getAttribute('rel') ?? ''));
            }
        }
    }


    private static function nativeRemoveComments( \Dom\Node $node ) : void
    {
        $child = $node->firstChild;
        while( $child !== null ) {
            $next = $child->nextSibling;
            if( $child instanceof \Dom\Comment ) {
                $node->removeChild( $child );
            } elseif( $child->hasChildNodes() ) {
                self::nativeRemoveComments( $child );
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
    private static function nativeStripTemplateContent( \Dom\XPath $xpath ) : void
    {
        foreach( $xpath->document->querySelectorAll('template') as $node ) {
            $node->parentNode?->replaceChild( $node->cloneNode(false), $node );
        }
    }


    private static function nativeCheckMetaRefresh( \Dom\XPath $xpath ) : void
    {
        foreach ($xpath->document->querySelectorAll('meta[content]') as $node) {
            if( self::metaRefreshBlocked($node->getAttribute('content') ?? '', $node->getAttribute('http-equiv') ?? '') ) {
                $node->removeAttribute('content');
            }
        }
    }


    private static function nativeDropRawTextBreakouts( \Dom\XPath $xpath ) : void
    {
        foreach( $xpath->document->querySelectorAll('style, script') as $node ) {
            $tag = strtolower( (string) $node->localName );
            if( preg_match( '#</' . $tag . '[\s/>]#i', (string) $node->textContent ) ) {
                $node->parentNode?->removeChild( $node );
            }
        }
    }


    private static function nativeDropInlineScripts( \Dom\XPath $xpath ) : void
    {
        foreach ($xpath->document->querySelectorAll('script') as $node) {
            if( trim($node->getAttribute('src') ?? '') === '' ) {
                $node->parentNode?->removeChild($node);
            }
        }
    }


    private static function nativeUnwrapStructural( \Dom\XPath $xpath ) : void
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


    private static function nativeSerializeBody( \Dom\HTMLDocument $doc ) : string
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
    private static function nativeFilterByUri( \Dom\XPath $xpath, string $tag, array $uris ) : void
    {
        $uriAttr = self::$tagUriAttr[$tag] ?? null;
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
            if( !$val || !self::isAllowedUri( $val, $uris ) || self::isBlockedUri( $val ) )
            {
                $node->parentNode?->removeChild( $node );
                continue;
            }
            self::nativeHardenAttributes( $node, $tag );
        }
    }


    private static function nativeRestrictBaseHref( \Dom\XPath $xpath ) : void
    {
        foreach( $xpath->document->querySelectorAll('base[href]') as $node ) {
            if( self::baseHrefCrossOrigin( $node->getAttribute('href') ?? '' ) ) {
                $node->removeAttribute('href');
            }
        }
    }


    private static function nativeHardenAllowed( \Dom\XPath $xpath, string $tag ) : void
    {
        if( !isset( self::$safeAttrs[$tag] ) ) {
            return;
        }
        foreach( $xpath->document->querySelectorAll($tag) as $node ) {
            self::nativeHardenAttributes( $node, $tag );
        }
    }


    private static function nativeHardenAttributes( \Dom\Element $node, string $tag ) : void
    {
        if( !isset( self::$safeAttrs[$tag] ) ) {
            return;
        }
        $safe = self::$safeAttrs[$tag];
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
            $allow = self::filterAllowFeatures( $node->getAttribute( 'allow' ) ?? '' );
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
        $animSet = array_flip( self::$unsafeSvgElements );
        $blockedSet = array_flip( self::$blockedNames );
        $uriSet = array_flip( self::$uriAttributes );

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
                if (self::uriValueBlocked($local, trim($attribute->value))) {
                    $remove[] = $attribute;
                }
            }
            foreach ($remove as $attribute) {
                $node->removeAttributeNode($attribute);
            }

            if( $newWindow && ($tag === 'a' || $tag === 'area' || $tag === 'form') ) {
                $node->setAttribute('rel', self::mergeRel($node->getAttribute('rel')));
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
                && self::metaRefreshBlocked($node->getAttribute('content'), $node->getAttribute('http-equiv'))
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
            if( $node instanceof \DOMElement && self::baseHrefCrossOrigin( $node->getAttribute('href') ) ) {
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
                $attrsToRemove[] = $attr;
            }
        }

        foreach( $attrsToRemove as $attr ) {
            $node->removeAttributeNode( $attr );
        }

        // Restrict the iframe Permissions-Policy "allow" attribute to safe
        // features so an allowed embed can't request e.g. camera or microphone.
        if( $tag === 'iframe' && $node->hasAttribute( 'allow' ) ) {
            $allow = self::filterAllowFeatures( $node->getAttribute( 'allow' ) );
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
     * depth (self::MAX_DEPTH), element-count (self::MAX_ELEMENTS), stray-"<"
     * (self::MAX_STRAY), attribute-cost (self::MAX_ATTR_WORK), swallowed-"<"
     * (self::MAX_SWALLOW) or unmatched-end-tag (self::MAX_MISMATCH) limits, used to
     * reject pathological input before the
     * parser and the per-element pipeline run on it — each cap fences off an input
     * class that drives the parser or pipeline into superlinear time. It mirrors
     * the parser closely enough not to be gamed
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
        $stray = 0;         // stray "<" feeding the parser's O(n^2) character path
        $attrWork = 0;      // running sum of attrs^2 — the parser's per-element attribute cost
        $swallowed = 0;     // "<" consumed inside tags — feeds the parser's O(n^2) reconstruction
        $mismatch = 0;      // unmatched end tags — feed the parser's O(n^2) foster-parenting work
        $len = strlen( $input );
        $offset = 0;

        while( ($pos = strpos( $input, '<', $offset )) !== false )
        {
            $offset = $pos + 1;
            $ch = $input[$offset] ?? '';

            if( $ch === '/' )   // end tag — pop down to the matching open, if any
            {
                $name = self::tagName( $input, $offset + 1, $len );
                $selfClosing = false;
                $attrs = 0;
                $sw = 0;
                $end = self::tagEnd( $input, $offset + 1, $len, $selfClosing, $attrs, $sw );
                if( ($attrWork += $attrs * $attrs) > self::MAX_ATTR_WORK
                    || ($swallowed += $sw) > self::MAX_SWALLOW ) {
                    return true;
                }
                $matched = false;
                for( $i = count( $stack ) - 1; $i >= 0; $i-- ) {
                    if( $stack[$i] === $name ) {
                        array_splice( $stack, $i );
                        array_splice( $foreign, $i );
                        $matched = true;
                        break;
                    }
                }
                // An end tag with no matching open is malformed; the parser handles
                // each via foster-parenting/adoption-agency work that grows ~O(n^2)
                // (e.g. "<dd></a></div><td></p></div>") yet is invisible to the
                // depth/element caps. Legit markup has ~none, so bound the count.
                if( !$matched && ++$mismatch > self::MAX_MISMATCH ) {
                    return true;
                }
                $inForeign = $foreign === [] ? false : $foreign[count( $foreign ) - 1];
                // Skip the tag body so its quoted "<"/">" aren't rescanned; if the
                // tag was cut short by a restarting "<", re-read that "<" next.
                $offset = ( $end < $len && $input[$end] === '>' ) ? $end + 1 : $end;
                continue;
            }

            if( !ctype_alpha( $ch ) ) {
                // "<!" (comments/declarations) and "<?" (PIs) tokenize cheaply, but
                // any other non-tag "<" (e.g. "<<", "< ", "<1") falls to Masterminds'
                // ~O(n^2) character-token path that the depth/element caps don't see;
                // bound how many we accept so a stray-"<" flood can't hang the parser.
                if( $ch !== '!' && $ch !== '?' && ++$stray > self::MAX_STRAY ) {
                    return true;
                }
                continue;       // comment, declaration, processing instruction or stray "<"
            }

            if( ++$total > self::MAX_ELEMENTS ) {
                return true;
            }

            $name = self::tagName( $input, $offset, $len );
            // Find the real end of the tag, honoring quoted/unquoted attribute
            // values, so a "/>" hidden inside a value (e.g. <g x="a/>b">) can't pose
            // as a self-closing tag and let deeply nested foreign content sneak past
            // the depth guard. Advancing past the end also skips attribute-soup "<".
            $selfClosing = false;
            $attrs = 0;
            $sw = 0;
            $end = self::tagEnd( $input, $offset, $len, $selfClosing, $attrs, $sw );
            $offset = ( $end < $len && $input[$end] === '>' ) ? $end + 1 : $end;

            // Building an element is ~O(attrs^2) in the parser (duplicate-name
            // checks), and a "<" swallowed by a malformed tag drives ~O(n^2)
            // adoption-agency/reconstruction — both invisible to the element/depth
            // caps. Bound the summed attribute cost and the swallowed-"<" count so
            // neither a huge attribute list nor a flood of malformed tags hangs it.
            if( ($attrWork += $attrs * $attrs) > self::MAX_ATTR_WORK
                || ($swallowed += $sw) > self::MAX_SWALLOW ) {
                return true;
            }

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


    /**
     * Scans a tag starting at $start (its first name character) and returns the
     * index at which it ends, mirroring how the parser tokenizes a tag: a ">" or
     * "/>" inside a quoted ("…"/'…') or unquoted attribute value does NOT end the
     * tag. A "<" followed by a letter starts a new tag (the parser abandons the
     * current one — so "<br<br" is two tags); a "<" before anything else (e.g.
     * "</a>") is consumed as part of the current tag, as the parser does. A quoted
     * value is only entered
     * after "="; a bare "'"/'"' in attribute-name position is an ordinary name
     * character (matching the tokenizer), so it can't swallow the rest of the input.
     * $selfClosing is set only when the tag ends with a real tag-level "/>",
     * $attrs to the number of attributes (each preceded by a whitespace run, incl.
     * the run after an unquoted value), and $swallowed to the number of stray "<"
     * the tag consumes (a malformed-markup signal — see exceedsLimits). Returns the
     * index of the ending ">" or restarting "<" (the caller re-reads a "<"), or
     * $len at EOF.
     */
    private static function tagEnd( string $input, int $start, int $len, bool &$selfClosing, int &$attrs, int &$swallowed ) : int
    {
        $selfClosing = false;
        $attrs = 0;
        $swallowed = 0;
        $state = 0;     // 0=tag, 1=double-quoted value, 2=single-quoted value, 3=unquoted value, 4=after "="
        $prevSlash = false;
        $inSpace = false;

        for( $i = $start; $i < $len; $i++ ) {
            $c = $input[$i];

            if( $state === 1 ) { if( $c === '"' ) { $state = 0; } $inSpace = false; continue; }
            if( $state === 2 ) { if( $c === "'" ) { $state = 0; } $inSpace = false; continue; }
            if( $state === 3 ) {                        // unquoted value: ">" ends it, "<"/"/" are literal
                if( $c === '>' ) { return $i; }
                if( $c === '<' ) { $swallowed++; $inSpace = false; continue; }
                if( ctype_space( $c ) ) {               // value ended; this run precedes the next attribute
                    $state = 0;
                    $attrs++;
                    $inSpace = true;
                } else {
                    $inSpace = false;
                }
                continue;
            }
            if( $state === 4 ) {                        // just saw "=", a value is about to start
                if( ctype_space( $c ) ) { continue; }
                if( $c === '"' ) { $state = 1; }
                elseif( $c === "'" ) { $state = 2; }
                elseif( $c === '>' ) { return $i; }
                else { if( $c === '<' ) { $swallowed++; } $state = 3; }
                $inSpace = false;
                continue;
            }

            // state 0 — within the tag, not inside an attribute value
            if( $c === '>' ) { $selfClosing = $prevSlash; return $i; }
            // "<" + a letter starts a new tag (the parser abandons this one — so
            // "<br<br" is two tags); "<" before anything else (e.g. "</a>", "< ")
            // is consumed as part of this tag, exactly as the parser does — so a
            // "<a \"</a>" can't fool the main loop into popping a tag the parser
            // actually keeps open (which would hide deep nesting from the cap). A
            // consumed "<" is counted: it only arises from malformed markup and is
            // what feeds the parser's O(n^2) reconstruction (see exceedsLimits).
            if( $c === '<' ) {
                if( $i + 1 < $len && ctype_alpha( $input[$i + 1] ) ) { return $i; }
                $swallowed++;
            }
            if( ctype_space( $c ) ) {                   // each whitespace run precedes a new attribute
                if( !$inSpace ) { $attrs++; }
                $inSpace = true;
                $prevSlash = false;
                continue;
            }
            $inSpace = false;
            if( $c === '=' ) { $state = 4; }            // only "=" starts a value; "'"/'"' are name chars
            $prevSlash = ( $c === '/' );
        }

        return $len;
    }


    /**
     * Normalizes a URL to what the scheme actually resolves to after serialization.
     * Browsers strip only TAB/LF/CR from URLs, but libxml's saveHTML drops every C0
     * control character when it serializes the attribute, so a value like
     * "java<0x01>script:" passes a naive scheme check yet is emitted as a live
     * "javascript:" URL. Removing all C0 controls (and DEL) anywhere — plus leading
     * control characters and whitespace — keeps the scheme check in sync with the
     * serialized output and can only make detection stricter (no valid URL contains
     * a raw control byte).
     */
    private static function stripUrlControlChars( string $value ) : string
    {
        $value = (string) preg_replace('/[\x00-\x1f\x7f]/', '', $value);
        return (string) preg_replace('/^[\x00-\x20]+/', '', $value);
    }


    private static function isBlockedUri( string $value ) : bool
    {
        // Normalize the way a browser does before resolving the scheme, so
        // payloads like "java&#9;script:" or a leading "\x01javascript:" can't
        // slip past the scheme detection below.
        $value = self::stripUrlControlChars( $value );

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


    /**
     * Whether a URI attribute value uses a blocked scheme; a "srcset" value is
     * split into its candidate URLs first. Backend-independent so both the legacy
     * and native attribute passes share one rule.
     */
    private static function uriValueBlocked( ?string $local, string $value ) : bool
    {
        if ($local === 'srcset') {
            foreach (preg_split('/\s*,\s*/', $value) ?: [] as $entry) {
                $url = (preg_split('/\s+/', trim($entry)) ?: [])[0] ?? '';
                if (self::isBlockedUri($url)) {
                    return true;
                }
            }
            return false;
        }
        return self::isBlockedUri($value);
    }


    /**
     * Adds rel="noopener noreferrer" to an existing rel value, preserving its
     * other tokens. Hardens links/forms that open a separate browsing context.
     */
    private static function mergeRel( string $rel ) : string
    {
        $tokens = preg_split('/\s+/', trim($rel), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        foreach (['noopener', 'noreferrer'] as $token) {
            if( !in_array($token, $tokens, true) ) {
                $tokens[] = $token;
            }
        }
        return implode(' ', $tokens);
    }


    /**
     * Restricts an iframe "allow" Permissions-Policy value to the safe feature
     * list, returning the rebuilt value ("" when nothing survives).
     */
    private static function filterAllowFeatures( string $allow ) : string
    {
        $kept = [];
        foreach( explode(';', $allow) as $directive ) {
            $directive = trim($directive);
            $feature = strtolower( (preg_split('/\s+/', $directive) ?: [''])[0] );
            if( $directive !== '' && in_array($feature, self::$safeAllowFeatures, true) ) {
                $kept[] = $directive;
            }
        }
        return implode('; ', $kept);
    }


    /**
     * Whether a <base> href points off the current origin (absolute or
     * protocol-relative), normalized like a browser (strip control chars, treat
     * backslashes as slashes) so "\\evil", "/\evil" and "ht&#9;tps://evil" can't
     * slip past the cross-origin test.
     */
    private static function baseHrefCrossOrigin( string $href ) : bool
    {
        $href = str_replace('\\', '/', self::stripUrlControlChars($href));
        return str_starts_with($href, '//') || (bool) preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*:#', $href);
    }


    /**
     * Whether a <meta http-equiv="refresh"> content value redirects via a blocked
     * scheme. Control chars are stripped first (an embedded one would terminate
     * the URL extraction early and is dropped on serialize anyway) and the
     * whitespace groups are possessive so all-whitespace content can't backtrack
     * quadratically before the required URL token.
     */
    private static function metaRefreshBlocked( string $content, string $httpEquiv ) : bool
    {
        if( strcasecmp($httpEquiv, 'refresh') !== 0 ) {
            return false;
        }
        $content = (string) preg_replace('/[\x00-\x1f\x7f]/', '', $content);
        return preg_match('/^\s*+[\d.]*+\s*+[;,]?\s*+(?:url\s*+=\s*+)?["\']?\s*+([^"\'\s>]+)/i', $content, $m) === 1
            && self::isBlockedUri($m[1]);
    }
}
