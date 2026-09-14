<?php

namespace Aimeos\Sanitizer;


/**
 * Public entry point: rejects hostile input, then dispatches to the DOM backend
 * matching the PHP version. The security policy lives in Policy, the DoS pre-scan
 * in Limits, and the parse → sanitize → serialize pipelines in NativeBackend
 * (PHP 8.4+, lexbor) and LegacyBackend (PHP 8.0-8.3, Masterminds).
 */
class Sane
{
    /**
     * Sanitizes the HTML input, removing potentially dangerous content.
     *
     * The $allow map opts specific blocked elements back in, keyed by tag name:
     * - true keeps the element regardless of its URL. Event handlers, "style"
     *   attributes and dangerous-scheme URLs are still stripped, and inline
     *   <script> is dropped (only scripts loading from an external src are
     *   kept). Other inline content such as <style> CSS is kept verbatim, so
     *   only pass true for tags you fully trust.
     * - list<string> keeps the element only when its URL matches one of the
     *   given origin/path prefixes; embedding tags receive a restricted attribute
     *   list and iframes are sandboxed. Ambiguous URLs and dot segments are rejected.
     *
     * @param array<string, bool|list<string>> $allow
     */
    public static function html( string $input, array $allow = [] ) : string
    {
        return self::sanitize( $input, $allow, false );
    }


    /**
     * Sanitizes untrusted rich text using fixed HTML element/attribute allow-lists.
     * Removes unknown elements with their contents and all id/name attributes.
     * Executable content cannot be enabled in this profile.
     */
    public static function strict( string $input ) : string
    {
        return self::sanitize( $input, [], true );
    }


    /** @param array<string, bool|list<string>> $allow */
    private static function sanitize( string $input, array $allow, bool $strict ) : string
    {
        // Reject hostile input before the parser and pipeline run on it. The caps
        // fence off the input classes that drive the (Masterminds) parser's O(n^2)
        // paths or the per-element pipeline into superlinear time.
        if( Limits::exceeds( $input ) ) {
            return '';
        }

        // Use the native HTML5 parser where available. Both backends still need
        // resource limits, including checks on the tree produced by the parser.
        if( class_exists( '\Dom\HTMLDocument' ) ) {
            return NativeBackend::sanitize( $input, $allow, $strict );
        }

        return LegacyBackend::sanitize( $input, $allow, $strict );
    }
}
