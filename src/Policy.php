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
    // which the legacy parser may interpret differently.
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

    /** @var list<string> Rich-text HTML only; unknown elements and their children are removed. */
    public const STRICT_ELEMENTS = [
        'a', 'abbr', 'address', 'article', 'aside', 'b', 'bdi', 'bdo', 'blockquote', 'br',
        'caption', 'cite', 'code', 'col', 'colgroup', 'dd', 'del', 'details', 'dfn', 'div',
        'dl', 'dt', 'em', 'figcaption', 'figure', 'footer', 'h1', 'h2', 'h3', 'h4', 'h5',
        'h6', 'header', 'hgroup', 'hr', 'i', 'img', 'ins', 'kbd', 'li', 'main', 'mark',
        'nav', 'ol', 'p', 'pre', 'q', 'rp', 'rt', 'ruby', 's', 'samp', 'section', 'small',
        'span', 'strong', 'sub', 'summary', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
        'thead', 'time', 'tr', 'u', 'ul', 'var', 'wbr'
    ];

    /** @var list<string> No id/name, class, data-*, is, or framework directives. */
    public const STRICT_GLOBAL_ATTRS = ['title', 'lang', 'dir', 'aria-label'];

    /** @var array<string, list<string>> */
    public const STRICT_ATTRS = [
        'a' => ['href', 'target', 'rel'],
        'blockquote' => ['cite'], 'q' => ['cite'],
        'col' => ['span'], 'colgroup' => ['span'],
        'del' => ['cite', 'datetime'], 'ins' => ['cite', 'datetime'],
        'details' => ['open'],
        'img' => ['src', 'alt', 'width', 'height', 'loading', 'decoding'],
        'li' => ['value'], 'ol' => ['start', 'reversed', 'type'],
        'td' => ['colspan', 'rowspan'], 'th' => ['colspan', 'rowspan', 'scope', 'abbr'],
        'time' => ['datetime'],
    ];


    /** @param array<string, bool|list<string>> $allow */
    public static function elementBlocked( string $tag, string $uri, array $allow, bool $strict ) : bool
    {
        if( $strict ) {
            return !in_array( $tag, self::STRICT_ELEMENTS, true );
        }
        if( in_array( strtolower($tag), self::UNSAFE_SVG_ELEMENTS, true ) ) {
            return true;
        }
        if( !in_array( $tag, self::REMOVE_ELEMENTS, true ) || ($allow[$tag] ?? false) === true ) {
            return false;
        }
        $prefixes = $allow[$tag] ?? false;
        return !isset( self::TAG_URI_ATTR[$tag] ) || !is_array( $prefixes )
            || !self::isAllowedUri( $uri, array_values(array_filter($prefixes, 'is_string')) ) || self::isBlockedUri( $uri );
    }


    public static function attributeBlocked( string $tag, string $name, ?string $local, string $value, bool $strict ) : bool
    {
        if( $strict && !in_array( $name, self::STRICT_GLOBAL_ATTRS, true )
            && !in_array( $name, self::STRICT_ATTRS[$tag] ?? [], true ) ) {
            return true;
        }
        if( stripos( $name, 'on' ) === 0 || $name === 'style' || ($tag === 'base' && $name === 'target') ) {
            return true;
        }
        if( $name === 'id' || $name === 'name' ) {
            return in_array( $value, self::BLOCKED_NAMES, true );
        }
        if( !in_array( $name, self::URI_ATTRIBUTES, true ) && !in_array( $local, self::URI_ATTRIBUTES, true ) ) {
            return false;
        }
        if( $strict ) {
            $url = self::stripUrlControlChars( $value );
            if( preg_match( '/^([a-z][a-z0-9+.-]*):/i', $url, $match ) ) {
                $schemes = $tag === 'a' ? ['http', 'https', 'mailto', 'tel'] : ['http', 'https'];
                if( !in_array( strtolower($match[1]), $schemes, true )
                    && !($tag === 'img' && $name === 'src' && strtolower($match[1]) === 'data') ) {
                    return true;
                }
            }
        }
        return self::uriValueBlocked( $local, trim($value) );
    }


    public static function opensNewContext( string $target ) : bool
    {
        // Browsers compare target keywords without trimming whitespace.
        return !in_array( strtolower($target), ['', '_self', '_parent', '_top'], true );
    }


    /**
     * @param list<string> $uris
     */
    public static function isAllowedUri( string $src, array $uris ) : bool
    {
        $candidate = self::uriParts( $src );
        if( $candidate === null ) {
            return false;
        }
        $boundary = ['/', '?', '#'];

        foreach( $uris as $uri )
        {
            $prefix = self::uriParts( trim($uri) );
            if( $prefix === null || $candidate[0] !== $prefix[0] ) {
                continue;
            }
            [$src, $uri] = [$candidate[1], $prefix[1]];
            if( !str_starts_with( $src, $uri ) ) {
                continue;
            }
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
     * Compare a conservative URL subset whose browser interpretation is unambiguous.
     * Scheme/host/default ports are normalized; path/query/fragment keep their case.
     * Reject controls, backslashes, credentials and dot segments instead of trying
     * to resolve them without a document base URL. IDN hosts must use ASCII punycode.
     *
     * @return array{string, string}|null Origin (or relative kind), path with suffix
     */
    private static function uriParts( string $url ) : ?array
    {
        if( $url === '' || preg_match( '/[\x00-\x20\x7f\\\\]/', $url ) ) {
            return null;
        }
        $origin = '';
        $resource = $url;
        if( preg_match( '~^(?:(https?):)?//([^/?#]+)(.*)$~iD', $url, $match ) ) {
            if( !preg_match( '/^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::([0-9]{1,5}))?$/iD', $match[2], $host ) ) {
                return null;
            }
            $scheme = strtolower( $match[1] );
            $port = isset($host[2]) ? (int) $host[2] : null;
            if( $port !== null && $port > 65535 ) {
                return null;
            }
            if( ($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443) ) {
                $port = null;
            }
            $origin = ($scheme === '' ? '' : $scheme . ':') . '//' . strtolower($host[1])
                . ($port === null ? '' : ':' . $port);
            $resource = $match[3];
            if( !str_starts_with( $resource, '/' ) ) {
                $resource = '/' . $resource;
            }
        } elseif( str_starts_with($url, '//') || preg_match('/^[a-z][a-z0-9+.-]*:/i', $url) ) {
            return null;
        }
        $path = substr( $resource, 0, strcspn($resource, '?#') );
        if( preg_match( '~(?:^|/)(?:\.|%2e){1,2}(?:/|$)~i', $path ) ) {
            return null;
        }
        return [$origin, $resource];
    }


    /**
     * Conservatively normalize schemes before checking them. Browsers remove
     * TAB/LF/CR within URLs. Strip all C0 controls and DEL for this check so a
     * later serializer that removes more controls cannot revive a blocked scheme.
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
     * Whether a URI attribute value uses a blocked scheme. URL lists are scanned
     * one token at a time so large attributes do not allocate large token arrays.
     */
    public static function uriValueBlocked( ?string $local, string $value ) : bool
    {
        if( $local === 'ping' ) {
            // Hyperlink auditing splits on HTML ASCII whitespace, not commas.
            $whitespace = " \t\r\n\f";
            $length = strlen($value);
            $offset = 0;
            while( $offset < $length ) {
                $offset += strspn($value, $whitespace, $offset);
                $size = strcspn($value, $whitespace, $offset);
                if( self::isBlockedUri(substr($value, $offset, $size)) ) {
                    return true;
                }
                $offset += $size;
            }
            return false;
        }
        if( $local !== 'srcset' ) {
            return self::isBlockedUri($value);
        }

        // Follow HTML's srcset URL boundaries: commas inside URL tokens (e.g.
        // data:image/png,...) are data; only trailing commas end a candidate.
        // Check URLs even when their descriptors are invalid. Descriptor syntax
        // and image selection are left to the browser.
        // https://html.spec.whatwg.org/multipage/images.html#parsing-a-srcset-attribute
        $whitespace = " \t\r\n\f";
        $length = strlen($value);
        $offset = 0;
        while( $offset < $length ) {
            $offset += strspn($value, $whitespace . ',', $offset);
            if( $offset === $length ) {
                break;
            }
            $size = strcspn($value, $whitespace, $offset);
            $url = substr($value, $offset, $size);
            $offset += $size;
            if( self::isBlockedUri(rtrim($url, ',')) ) {
                return true;
            }
            if( str_ends_with($url, ',') ) {
                continue;
            }

            // Descriptor commas inside parentheses do not split candidates.
            // This state is deliberately not nested, matching HTML's tokenizer.
            $inParens = false;
            while( $offset < $length ) {
                $char = $value[$offset++];
                if( $inParens ) {
                    $inParens = $char !== ')';
                } elseif( $char === ',' ) {
                    break;
                } elseif( $char === '(' ) {
                    $inParens = true;
                }
            }
        }
        return false;
    }


    /**
     * Adds rel="noopener noreferrer" to an existing rel value, preserving its
     * other tokens. Hardens links/forms that open a separate browsing context.
     */
    public static function mergeRel( string $rel ) : string
    {
        // Normalize separators without allocating an array entry for every token.
        $rel = trim((string) preg_replace('/\s+/', ' ', trim($rel)), ' ');
        $padded = ' ' . $rel . ' ';
        foreach( ['noopener', 'noreferrer'] as $token ) {
            if( !str_contains($padded, ' ' . $token . ' ') ) {
                $rel .= ($rel === '' ? '' : ' ') . $token;
            }
        }
        return $rel;
    }


    /**
     * Restricts an iframe "allow" Permissions-Policy value to the safe feature
     * list, returning the rebuilt value ("" when nothing survives).
     */
    public static function filterAllowFeatures( string $allow ) : string
    {
        $kept = '';
        $offset = 0;
        $length = strlen($allow);
        // Scan one directive and its feature name at a time. Neither the full
        // directive list nor the unused origin tokens need to become arrays.
        while( $offset < $length ) {
            $end = strpos($allow, ';', $offset);
            $end = $end === false ? $length : $end;
            $directive = trim(substr($allow, $offset, $end - $offset));
            $offset = $end + 1;
            $feature = strtolower(substr($directive, 0, strcspn($directive, " \t\r\n\f\v")));
            if( $directive !== '' && in_array($feature, self::SAFE_ALLOW_FEATURES, true) ) {
                $kept .= ($kept === '' ? '' : '; ') . $directive;
            }
        }
        return $kept;
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
     * Extract the explicit redirect URL from a meta refresh; null means invalid
     * syntax or a reload without a URL. Keep URL controls and whitespace intact
     * for prefix validation, and leave scheme normalization to isBlockedUri().
     * The forward scans follow HTML's refresh boundaries without backtracking.
     * https://html.spec.whatwg.org/multipage/semantics.html#shared-declarative-refresh-steps
     */
    public static function metaRefreshUrl( string $content ) : ?string
    {
        $whitespace = " \t\r\n\f";
        $length = strlen($content);
        $offset = strspn($content, $whitespace);
        // HTML permits a leading dot and ignores the fractional part of a delay.
        $size = strspn($content, '0123456789.', $offset);
        if( $size === 0 ) {
            return null;
        }
        $offset += $size;
        if( $offset === $length || !str_contains($whitespace . ';,', $content[$offset]) ) {
            return null;
        }
        $offset += strspn($content, $whitespace, $offset);
        if( in_array($content[$offset] ?? '', [';', ','], true) ) {
            $offset++;
        }
        $offset += strspn($content, $whitespace, $offset);
        if( $offset === $length ) {
            return null;
        }
        if( strcasecmp(substr($content, $offset, 3), 'url') === 0 ) {
            $equals = $offset + 3;
            $equals += strspn($content, $whitespace, $equals);
            if( ($content[$equals] ?? '') === '=' ) {
                $offset = $equals + 1;
                $offset += strspn($content, $whitespace, $offset);
            }
        }
        // Only a matching closing quote terminates a quoted URL. Spaces,
        // opposite quotes and '>' are URL data, not extraction boundaries.
        if( in_array($content[$offset] ?? '', ['"', "'"], true) ) {
            $quote = $content[$offset++];
            $end = strpos($content, $quote, $offset);
            return substr($content, $offset, ($end === false ? $length : $end) - $offset);
        }
        return substr($content, $offset);
    }
}
