<?php

namespace Aimeos\Sanitizer;


/**
 * Backend-independent security policy: the element/attribute allow- and
 * deny-lists plus the pure URL/scheme/value rules both DOM backends apply.
 * Holds no DOM state, so every method is a pure function of its arguments and
 * the two backends (NativeBackend, LegacyBackend) share one rule set.
 */
class Policy
{
    // Unsafe elements to remove completely. Includes raw-text elements
    // (plaintext, xmp, noembed, noframes) whose content browsers parse as text
    // but the libxml DOM does not, to avoid parser-differential surprises.
    /** @var list<string> */
    public const REMOVE_ELEMENTS = ['applet', 'base', 'embed', 'form', 'frame', 'iframe', 'link', 'math', 'meta', 'noembed', 'noframes', 'noscript', 'object', 'plaintext', 'portal', 'script', 'style', 'svg', 'template', 'xmp'];

    // SVG elements that carry or set script (SMIL animation, XML-Events handler);
    // always removed, even inside an allowed <svg>. Matched case-insensitively.
    /** @var list<string> */
    public const UNSAFE_SVG_ELEMENTS = ['animate', 'animatemotion', 'animatetransform', 'animatecolor', 'set', 'handler'];

    // Attributes that may contain URIs
    /** @var list<string> */
    public const URI_ATTRIBUTES = [
        'href', 'src', 'xlink:href', 'formaction', 'action', 'background', 'poster', 'ping', 'srcset', 'data',
        'cite', 'longdesc'
    ];

    // Disallowed URI schemes
    /** @var list<string> */
    public const BLOCKED_SCHEMES = ['javascript', 'vbscript', 'file', 'filesystem', 'blob'];

    // Allowed MIME types for data: URIs
    /** @var list<string> */
    public const ALLOWED_DATA_MIMES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

    // Tag to URI attribute mapping
    /** @var array<string, string> */
    public const TAG_URI_ATTR = [
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
    public const SAFE_ATTRS = [
        'embed'  => ['src', 'width', 'height', 'type', 'title'],
        'iframe' => ['src', 'width', 'height', 'title', 'loading', 'allow', 'allowfullscreen', 'frameborder', 'sandbox'],
        'frame'  => ['src', 'name', 'title', 'frameborder', 'scrolling'],
        'object' => ['data', 'width', 'height', 'type', 'title'],
    ];

    // Permissions-Policy features allowed in an iframe "allow" attribute; covers
    // common media embeds while dropping powerful ones (camera, microphone,
    // geolocation, display-capture, usb, ...).
    /** @var list<string> */
    public const SAFE_ALLOW_FEATURES = [
        'accelerometer', 'autoplay', 'clipboard-write', 'encrypted-media',
        'fullscreen', 'gyroscope', 'picture-in-picture', 'web-share'
    ];

    // Best-effort DOM-clobbering denylist: id/name values that would shadow a
    // window/document/form property. Not exhaustive — see SANITIZE_DOM-style
    // checks for full coverage.
    /** @var list<string> */
    public const BLOCKED_NAMES = [
        'location', 'window', 'document', 'frames', 'self', 'parent', 'top',
        'opener', 'alert', 'confirm', 'prompt', 'navigator', 'history', 'event',
        'console', 'length', 'content', 'forms', 'images', 'anchors', 'links',
        'scripts', 'embeds', 'plugins', 'applets', 'all', 'cookie', 'domain',
        'referrer', 'defaultView', 'documentElement', 'body', 'head',
        'getElementById', 'getElementsByName', 'createElement', 'write',
        'writeln', 'querySelector', 'querySelectorAll'
    ];


    /**
     * @param list<string> $uris
     */
    public static function isAllowedUri( string $src, array $uris ) : bool
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
     * Normalizes a URL to what the scheme actually resolves to after serialization.
     * Browsers strip only TAB/LF/CR from URLs, but libxml's saveHTML drops every C0
     * control character when it serializes the attribute, so a value like
     * "java<0x01>script:" passes a naive scheme check yet is emitted as a live
     * "javascript:" URL. Removing all C0 controls (and DEL) anywhere — plus leading
     * control characters and whitespace — keeps the scheme check in sync with the
     * serialized output and can only make detection stricter (no valid URL contains
     * a raw control byte).
     */
    public static function stripUrlControlChars( string $value ) : string
    {
        $value = (string) preg_replace('/[\x00-\x1f\x7f]/', '', $value);
        return (string) preg_replace('/^[\x00-\x20]+/', '', $value);
    }


    public static function isBlockedUri( string $value ) : bool
    {
        // Normalize the way a browser does before resolving the scheme, so
        // payloads like "java&#9;script:" or a leading "\x01javascript:" can't
        // slip past the scheme detection below.
        $value = self::stripUrlControlChars( $value );

        if (!preg_match('/^([a-zA-Z][a-zA-Z0-9+.-]*):/', $value, $matches)) {
            return false;
        }

        $scheme = strtolower($matches[1]);

        if (in_array($scheme, self::BLOCKED_SCHEMES, true)) {
            return true;
        }

        if ($scheme === 'data') {
            return !preg_match('#^data:\s*([\w/+-]+)\s*[;,]#i', $value, $mimeMatch)
                || !in_array(strtolower($mimeMatch[1]), self::ALLOWED_DATA_MIMES, true);
        }

        return false;
    }


    /**
     * Whether a URI attribute value uses a blocked scheme; a "srcset" value is
     * split into its candidate URLs first. Backend-independent so both the legacy
     * and native attribute passes share one rule.
     */
    public static function uriValueBlocked( ?string $local, string $value ) : bool
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
    public static function mergeRel( string $rel ) : string
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
    public static function filterAllowFeatures( string $allow ) : string
    {
        $kept = [];
        foreach( explode(';', $allow) as $directive ) {
            $directive = trim($directive);
            $feature = strtolower( (preg_split('/\s+/', $directive) ?: [''])[0] );
            if( $directive !== '' && in_array($feature, self::SAFE_ALLOW_FEATURES, true) ) {
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
    public static function baseHrefCrossOrigin( string $href ) : bool
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
    public static function metaRefreshBlocked( string $content, string $httpEquiv ) : bool
    {
        if( strcasecmp($httpEquiv, 'refresh') !== 0 ) {
            return false;
        }
        $content = (string) preg_replace('/[\x00-\x1f\x7f]/', '', $content);
        return preg_match('/^\s*+[\d.]*+\s*+[;,]?\s*+(?:url\s*+=\s*+)?["\']?\s*+([^"\'\s>]+)/i', $content, $m) === 1
            && self::isBlockedUri($m[1]);
    }
}
