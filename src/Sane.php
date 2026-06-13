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
     * - list<string> keeps the element only when its URL starts with one of the
     *   given prefixes; embedding tags are additionally reduced to a safe
     *   attribute allow-list and sandboxed.
     *
     * @param array<string, bool|list<string>> $allow
     */
    public static function html( string $input, array $allow = [] ) : string
    {
        // Reject hostile input before the parser and pipeline run on it. The caps
        // fence off the input classes that drive the (Masterminds) parser's O(n^2)
        // paths or the per-element pipeline into superlinear time.
        if( Limits::exceeds( $input ) ) {
            return '';
        }

        // PHP 8.4+: parse with the native, spec-compliant, O(n) HTML5 parser
        // (lexbor) and serialize with it too, so even crafted misnested tag soup
        // can't drive the parser into superlinear time. Falls back to the
        // Masterminds path on PHP 8.0-8.3.
        if( class_exists( '\Dom\HTMLDocument' ) ) {
            return NativeBackend::sanitize( $input, $allow );
        }

        return LegacyBackend::sanitize( $input, $allow );
    }
}
