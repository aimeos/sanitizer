<?php

namespace Aimeos\Sanitizer;


/**
 * DoS guard: a cheap, linear pre-scan that rejects hostile input before the HTML
 * parser and the per-element pipeline ever run on it. Each cap fences off an
 * input class that would otherwise drive the parser or pipeline into superlinear
 * time. Pure string scanning — no DOM, no policy lists.
 */
class Limits
{
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

    // Void elements never nest, so a trailing self-closing slash on them is moot.
    private const VOID_ELEMENTS = ['area' => 1, 'base' => 1, 'br' => 1, 'col' => 1, 'embed' => 1,
        'hr' => 1, 'img' => 1, 'input' => 1, 'keygen' => 1, 'link' => 1, 'meta' => 1,
        'param' => 1, 'source' => 1, 'track' => 1, 'wbr' => 1];

    // Elements whose content is HTML even inside SVG/MathML (self-close not honored there)
    private const HTML_CONTEXT_ELEMENTS = ['foreignobject' => 1, 'desc' => 1, 'title' => 1,
        'mi' => 1, 'mo' => 1, 'mn' => 1, 'ms' => 1, 'mtext' => 1, 'annotation-xml' => 1];

    // A start tag (key) implies the end of these currently-open elements (value set)
    private const IMPLIED_END_TAGS = [
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
    private const BLOCK_ELEMENTS = ['address' => 1, 'article' => 1, 'aside' => 1, 'blockquote' => 1,
        'details' => 1, 'div' => 1, 'dl' => 1, 'fieldset' => 1, 'figcaption' => 1,
        'figure' => 1, 'footer' => 1, 'form' => 1, 'h1' => 1, 'h2' => 1, 'h3' => 1,
        'h4' => 1, 'h5' => 1, 'h6' => 1, 'header' => 1, 'hgroup' => 1, 'main' => 1,
        'menu' => 1, 'nav' => 1, 'ol' => 1, 'p' => 1, 'pre' => 1, 'section' => 1,
        'table' => 1, 'ul' => 1];


    /**
     * Cheap linear pre-scan reporting whether the markup exceeds the length
     * (self::MAX_LENGTH), nesting depth (self::MAX_DEPTH), element-count
     * (self::MAX_ELEMENTS), stray-"<" (self::MAX_STRAY), attribute-cost
     * (self::MAX_ATTR_WORK), swallowed-"<" (self::MAX_SWALLOW) or unmatched-end-tag
     * (self::MAX_MISMATCH) limits, used to reject pathological input before the
     * parser and the per-element pipeline run on it — each cap fences off an input
     * class that drives the parser or pipeline into superlinear time. It mirrors
     * the parser closely enough not to be gamed
     * downward on depth: a close tag only pops a matching open (so bogus "</z>"
     * can't keep the depth low), a self-closing slash counts as nesting in HTML
     * ("<div/>" nests) but not in SVG/MathML, and the common implied end tags
     * are applied so omitted optional close tags on legitimate lists, tables and
     * paragraphs don't pile up.
     */
    public static function exceeds( string $input ) : bool
    {
        // The length cap also keeps the (Masterminds-specific) O(n^2) parser paths
        // bounded; on the native path it bounds the per-element pipeline and
        // attribute cost.
        if( strlen( $input ) > self::MAX_LENGTH ) {
            return true;
        }

        $stack = [];        // open element names
        $foreign = [];      // parallel: whether each open element holds SVG/MathML content
        $inForeign = false;
        $selfClosing = false;
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
                if( !self::consumeTag( $input, $offset + 1, $len, $offset, $attrWork, $swallowed, $selfClosing ) ) {
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
                $inForeign = self::inForeign( $foreign );
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
            // values, so a "/>" hidden in a value (e.g. <g x="a/>b">) can't pose as
            // a self-closing tag and let deeply nested foreign content sneak past
            // the depth guard. Advancing past the end also skips attribute-soup "<".
            if( !self::consumeTag( $input, $offset, $len, $offset, $attrWork, $swallowed, $selfClosing ) ) {
                return true;
            }

            // Void elements never nest; a self-closing slash only ends the tag
            // in SVG/MathML content, where "<circle/>" is a leaf.
            if( isset( self::VOID_ELEMENTS[$name] ) || ( $selfClosing && ( $inForeign || $name === 'svg' || $name === 'math' ) ) ) {
                continue;
            }

            // Apply implied end tags so omitted optional close tags don't pile up.
            while( $stack !== [] ) {
                $top = $stack[count( $stack ) - 1];
                if( isset( self::IMPLIED_END_TAGS[$name][$top] ) || ( $top === 'p' && isset( self::BLOCK_ELEMENTS[$name] ) ) ) {
                    array_pop( $stack );
                    array_pop( $foreign );
                } else {
                    break;
                }
            }
            $inForeign = self::inForeign( $foreign );

            $stack[] = $name;
            $foreign[] = $inForeign = $name === 'svg' || $name === 'math'
                ? true
                : ( isset( self::HTML_CONTEXT_ELEMENTS[$name] ) ? false : $inForeign );

            if( count( $stack ) > self::MAX_DEPTH ) {
                return true;
            }
        }

        return false;
    }


    /**
     * Scans the tag whose name starts at $nameStart, advances $offset past its end
     * (consuming a real ">", or re-reading a restarting "<" next), and folds the
     * tag's cost into the running budgets: building an element is ~O(attrs^2) in the
     * parser (duplicate-name checks) and a "<" swallowed by a malformed tag drives
     * ~O(n^2) adoption-agency/reconstruction — both invisible to the element/depth
     * caps. Returns false once either budget is exceeded, so neither a huge
     * attribute list nor a flood of malformed tags can hang the parser. $selfClosing
     * reports a real tag-level "/>".
     */
    private static function consumeTag( string $input, int $nameStart, int $len, int &$offset, int &$attrWork, int &$swallowed, bool &$selfClosing ) : bool
    {
        $attrs = 0;
        $sw = 0;
        $end = self::tagEnd( $input, $nameStart, $len, $selfClosing, $attrs, $sw );
        $offset = ( $end < $len && $input[$end] === '>' ) ? $end + 1 : $end;
        $attrWork += $attrs * $attrs;
        $swallowed += $sw;
        return $attrWork <= self::MAX_ATTR_WORK && $swallowed <= self::MAX_SWALLOW;
    }


    /**
     * Whether the innermost still-open element holds SVG/MathML content (false when
     * nothing is open). $foreign is the per-open-element flag stack.
     *
     * @param list<bool> $foreign
     */
    private static function inForeign( array $foreign ) : bool
    {
        return $foreign === [] ? false : $foreign[array_key_last( $foreign )];
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
     * the tag consumes (a malformed-markup signal — see consumeTag). Returns the
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
            // what feeds the parser's O(n^2) reconstruction (see consumeTag).
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
}
