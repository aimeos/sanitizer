<?php

namespace Aimeos\Sanitizer;


/**
 * DoS guard: a cheap, linear pre-scan that rejects hostile input before the HTML
 * parser and the per-element pipeline ever run on it. Caps bound parser work and
 * DOM allocations: many small nodes can exhaust memory well below the byte limit.
 * Pure string scanning — no DOM, no policy lists.
 */
class Limits
{
    // HTML whitespace excludes vertical tab, unlike ctype_space(). Treating it
    // as whitespace after '=' could hide real tags inside a false quoted value.
    private const WHITESPACE = " \t\r\n\f";

    // Resource limits for hostile input: deeply nested markup makes the HTML
    // parser run in roughly O(depth^2), and very large input is costly to
    // process. Input exceeding a limit is rejected (returns "").
    private const MAX_LENGTH = 4194304;   // 4 MiB
    private const MAX_DEPTH = 256;
    private const MAX_NODES = 50000;
    private const MAX_ATTRIBUTES = 100000;
    private const MAX_STRAY = 16384;      // stray "<" that hit the parser's O(n^2) path
    private const MAX_ATTR_WORK = 16000000;   // bounds the parser's ~O(attrs^2)-per-element cost
    private const MAX_SWALLOW = 2048;     // malformed "<" consumed inside tags (drives O(n^2) reconstruction)
    private const MAX_MISMATCH = 2048;    // unmatched end tags (drive O(n^2) foster-parenting/adoption work)

    private const TEXT_ELEMENTS = ['script', 'style', 'textarea', 'title', 'iframe', 'xmp', 'noembed', 'noframes'];

    // HTML's active formatting list survives closing an ancestor. Reconstructing
    // it can copy every unclosed formatting element on each later text/tag token.
    private const FORMATTING_ELEMENTS = ['a' => 1, 'b' => 1, 'big' => 1, 'code' => 1,
        'em' => 1, 'font' => 1, 'i' => 1, 'nobr' => 1, 's' => 1, 'small' => 1,
        'strike' => 1, 'strong' => 1, 'tt' => 1, 'u' => 1];

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
     * (self::MAX_LENGTH), nesting depth (self::MAX_DEPTH), node-count
     * (self::MAX_NODES), attribute-count (self::MAX_ATTRIBUTES), stray-"<"
     * (self::MAX_STRAY), attribute-cost (self::MAX_ATTR_WORK), swallowed-"<" (self::MAX_SWALLOW) or unmatched-end-tag
     * (self::MAX_MISMATCH) limits, used to reject pathological input before the
     * parser and the per-element pipeline run on it — each cap fences off an input
     * class that drives the parser or pipeline into superlinear time. This is a
     * conservative estimate, including possible formatting copies, supplemented
     * by checks on the parsed DOM. A close
     * tag only pops a matching open (so bogus "</z>"
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
        // The legacy decoder drops invalid UTF-8 bytes. Reject them before the
        // markup scan so decoding cannot expose tags or attributes it never saw.
        // Even an empty /u pattern validates the entire subject, without captures.
        if( preg_match('//u', $input) !== 1 ) {
            return true;
        }

        $stack = [];        // open element names
        $foreign = [];      // parallel: whether each open element holds SVG/MathML content
        $formatting = [];   // parallel: formatting tag's attribute count and byte length, or null
        $formatCost = [0, 0, 0]; // potentially active formatting nodes, attributes and markup bytes
        $formatNames = [];  // potentially active count per formatting tag name
        $copiedBytes = 0;
        $inForeign = false;
        $selfClosing = false;
        $total = 0;         // elements, text runs, comments and declarations
        $text = false;      // a text run is already counted until the next markup boundary
        $stray = 0;         // stray "<" feeding the parser's O(n^2) character path
        $attrWork = 0;      // running sum of attrs^2 — the parser's per-element attribute cost
        $attrTotal = 0;     // input attributes plus estimated formatting copies
        $swallowed = 0;     // "<" consumed inside tags — feeds the parser's O(n^2) reconstruction
        $mismatch = 0;      // unmatched end tags — feed the parser's O(n^2) foster-parenting work
        $len = strlen( $input );
        $offset = 0;
        $textElement = null;
        $foreignText = false;
        $scriptEscaped = false;

        while( ($pos = strpos( $input, '<', $offset )) !== false )
        {
            if( $pos > $offset && !$text ) {
                if( ++$total > self::MAX_NODES
                    || self::reconstructionExceeds($formatCost, $total, $attrTotal, $copiedBytes) ) {
                    return true;
                }
                $text = true;
            }
            $offset = $pos + 1;
            $ch = $input[$offset] ?? '';

            // Skip text only when both parsers agree where it ends. Leaving this
            // state early lets a text-only "<!--" hide later real parser work.
            if( $textElement !== null ) {
                $closing = '</' . $textElement;
                $matches = strncasecmp(substr($input, $pos, strlen($closing)), $closing, strlen($closing)) === 0;
                $next = $input[$pos + strlen($closing)] ?? '';
                if( !$matches || $next !== '>' ) {
                    if( !$text && ++$total > self::MAX_NODES ) {
                        return true;
                    }
                    $text = true;
                    // Foreign content and script double escapes have different
                    // text states in the two parsers. Reject ambiguous markup.
                    if( $foreignText || ($matches && $next !== '' && strpos(self::WHITESPACE . '/', $next) !== false) ) {
                        return true;
                    }
                    if( $textElement === 'script' ) {
                        if( substr_compare($input, '<!--', $pos, 4) === 0 ) {
                            $scriptEscaped = true;
                        } elseif( $scriptEscaped && strncasecmp(substr($input, $pos, 7), '<script', 7) === 0 ) {
                            return true;
                        }
                    }
                    continue;
                }
                $textElement = null;
                $scriptEscaped = false;
            }

            if( substr_compare($input, '<!--', $pos, 4) === 0 ) {
                if( ++$total > self::MAX_NODES ) {
                    return true;
                }
                $text = false;
                $start = $pos + 4;
                // HTML also permits abrupt empty comments and --!> endings.
                if( ($input[$start] ?? '') === '>' ) {
                    $offset = $start + 1;
                } elseif( substr($input, $start, 2) === '->' ) {
                    $offset = $start + 2;
                } elseif( preg_match('/--!?>/', $input, $end, PREG_OFFSET_CAPTURE, $start) ) {
                    $offset = $end[0][1] + strlen($end[0][0]);
                } else {
                    $offset = $len;
                }
                continue;
            }

            if( $ch === '!' || $ch === '?' ) {
                if( ++$total > self::MAX_NODES ) {
                    return true;
                }
                $text = false;
                if( !self::consumeDeclaration($input, $pos, $len, $offset) ) {
                    return true;
                }
                continue;
            }

            if( $ch === '/' )   // end tag — pop down to the matching open, if any
            {
                $text = false;
                $name = self::tagName( $input, $offset + 1, $len );
                if( $name === null || !self::consumeTag( $input, $offset + 1, $len, $offset, $attrWork, $attrTotal, $swallowed, $selfClosing ) ) {
                    return true;
                }
                $last = count($stack) - 1;
                // A misnested formatting end tag invokes the adoption agency
                // algorithm: up to eight rounds, with at most four clones each.
                if( ($formatNames[$name] ?? 0) > 0 && ($stack[$last] ?? null) !== $name
                    && self::reconstructionExceeds($formatCost, $total, $attrTotal, $copiedBytes, 32) ) {
                    return true;
                }
                $matched = false;
                for( $i = count( $stack ) - 1; $i >= 0; $i-- ) {
                    if( $stack[$i] === $name ) {
                        // Only a properly nested explicit close cancels a cost.
                        // Other popped formatting elements can remain active in
                        // the parser, so conservatively retain their cost to EOF.
                        if( $i === $last && $formatting[$i] !== null ) {
                            $formatNames[$name]--;
                            $formatCost[0]--;
                            $formatCost[1] -= $formatting[$i][0];
                            $formatCost[2] -= $formatting[$i][1];
                        }
                        array_splice( $stack, $i );
                        array_splice( $foreign, $i );
                        array_splice( $formatting, $i );
                        $matched = true;
                        break;
                    }
                }
                // An end tag with no matching open is malformed; the parser handles
                // each via foster-parenting/adoption-agency work that grows ~O(n^2)
                // (e.g. "<dd></a></div><td></p></div>") yet is invisible to the
                // depth/element caps. Legit markup has ~none, so bound the count.
                // An unmatched end tag can also create a node during recovery
                // (e.g. </p> or a bogus-comment end tag).
                if( !$matched && (++$mismatch > self::MAX_MISMATCH || ++$total > self::MAX_NODES) ) {
                    return true;
                }
                $inForeign = self::inForeign( $foreign );
                continue;
            }

            if( !ctype_alpha( $ch ) ) {
                if( !$text && (++$total > self::MAX_NODES
                    || self::reconstructionExceeds($formatCost, $total, $attrTotal, $copiedBytes)) ) {
                    return true;
                }
                $text = true;
                // A non-tag "<" (e.g. "<<", "< ", "<1") falls to Masterminds'
                // ~O(n^2) character-token path that the depth/element caps don't see;
                // bound how many we accept so a stray-"<" flood can't hang the parser.
                if( ++$stray > self::MAX_STRAY ) {
                    return true;
                }
                continue;
            }

            if( ++$total > self::MAX_NODES
                || self::reconstructionExceeds($formatCost, $total, $attrTotal, $copiedBytes) ) {
                return true;
            }
            $text = false;

            $name = self::tagName( $input, $offset, $len );
            if( $name === null ) {
                return true;
            }
            // Find the real end of the tag, honoring quoted/unquoted attribute
            // values, so a "/>" hidden in a value (e.g. <g x="a/>b">) can't pose as
            // a self-closing tag and let deeply nested foreign content sneak past
            // the depth guard. Advancing past the end also skips attribute-soup "<".
            $previousAttrs = $attrTotal;
            if( !self::consumeTag( $input, $offset, $len, $offset, $attrWork, $attrTotal, $swallowed, $selfClosing ) ) {
                return true;
            }
            $format = isset(self::FORMATTING_ELEMENTS[$name]) ? [$attrTotal - $previousAttrs, $offset - $pos] : null;
            if( $format !== null ) {
                $formatNames[$name] = ($formatNames[$name] ?? 0) + 1;
                $formatCost[0]++;
                $formatCost[1] += $format[0];
                $formatCost[2] += $format[1];
            }

            if( in_array($name, self::TEXT_ELEMENTS, true) ) {
                $textElement = $name;
                $foreignText = in_array('svg', $stack, true) || in_array('math', $stack, true);
                if( $foreignText && $selfClosing ) {
                    return true;
                }
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
                    array_pop( $formatting );
                } else {
                    break;
                }
            }
            $inForeign = self::inForeign( $foreign );

            $stack[] = $name;
            $formatting[] = $format;
            $foreign[] = $inForeign = $name === 'svg' || $name === 'math'
                ? true
                : ( isset( self::HTML_CONTEXT_ELEMENTS[$name] ) ? false : $inForeign );

            if( count( $stack ) > self::MAX_DEPTH ) {
                return true;
            }
        }

        // Count trailing text even when it contains no '<' to enter the loop.
        return $offset < $len && !$text && (++$total > self::MAX_NODES
            || self::reconstructionExceeds($formatCost, $total, $attrTotal, $copiedBytes));
    }


    /** Parsed node budgets include the document, doctype and html/head/body wrappers. */
    public static function treeExceeds( int $depth, int $nodes, int $attrWork, int $attributes ) : bool
    {
        return $depth > self::MAX_DEPTH + 2 || $nodes > self::MAX_NODES + 5
            || $attrWork > self::MAX_ATTR_WORK || $attributes > self::MAX_ATTRIBUTES;
    }


    /**
     * Charge possible formatting reconstruction even when the parser may avoid
     * it. This bounds copied nodes, attributes and large attribute values before
     * DOM allocation, without reproducing the browser's tree-repair algorithm.
     *
     * @param array{int, int, int} $cost Potentially active nodes, attributes, tag bytes
     */
    private static function reconstructionExceeds( array $cost, int &$nodes, int &$attrs, int &$bytes, int $rounds = 1 ) : bool
    {
        $nodes += $rounds * $cost[0];
        $attrs += $rounds * $cost[1];
        $bytes += $rounds * $cost[2];
        return $nodes > self::MAX_NODES || $attrs > self::MAX_ATTRIBUTES || $bytes > self::MAX_LENGTH;
    }


    /**
     * Consume declarations without treating their contents as tags or comments.
     * Masterminds and browsers disagree on CDATA, processing instructions and
     * malformed doctypes. Reject embedded markup and ambiguous quoted endings
     * instead of allowing either parser to hide work from the budgets.
     */
    private static function consumeDeclaration( string $input, int $start, int $len, int &$offset ) : bool
    {
        if( substr_compare($input, '<![CDATA[', $start, 9) === 0 ) {
            $end = strpos($input, ']]>', $start + 9);
            $offset = $end === false ? $len : $end + 3;
            $markup = strpos($input, '<', $start + 9);
            return $markup === false || $markup >= $offset;
        }

        $instruction = $input[$start + 1] === '?';
        $quote = null;
        for( $offset = $start + 2; $offset < $len; $offset++ ) {
            $ch = $input[$offset];
            if( $ch === '<' ) {
                return false;
            }
            if( $ch === '>' ) {
                if( $quote !== null || ($instruction && $input[$offset - 1] !== '?') ) {
                    return false;
                }
                $offset++;
                return true;
            }
            if( $ch === $quote ) {
                $quote = null;
            } elseif( $quote === null && ($ch === '"' || $ch === "'") ) {
                $quote = $ch;
            }
        }
        return true;
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
    private static function consumeTag( string $input, int $nameStart, int $len, int &$offset, int &$attrWork, int &$attrTotal, int &$swallowed, bool &$selfClosing ) : bool
    {
        $attrs = 0;
        $sw = 0;
        $end = self::tagEnd( $input, $nameStart, $len, $selfClosing, $attrs, $sw );
        $offset = ( $end < $len && $input[$end] === '>' ) ? $end + 1 : $end;
        $attrWork += $attrs * $attrs;
        $attrTotal += $attrs;
        $swallowed += $sw;
        return $attrWork <= self::MAX_ATTR_WORK && $attrTotal <= self::MAX_ATTRIBUTES && $swallowed <= self::MAX_SWALLOW;
    }


    /**
     * Whether the innermost still-open element holds SVG/MathML content (false when
     * nothing is open). $foreign is the per-open-element flag stack.
     *
     * @param list<bool> $foreign
     */
    private static function inForeign( array $foreign ) : bool
    {
        return $foreign === [] ? false : $foreign[count( $foreign ) - 1];
    }


    private static function tagName( string $input, int $start, int $len ) : ?string
    {
        // Include colons and underscores: script:x/script_x are not script.
        // Other characters produce different names in Masterminds and browsers;
        // reject those instead of truncating a name and changing parser state.
        $end = $start + strspn($input, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:_-', $start);
        if( $end < $len && strpos(self::WHITESPACE . '/>', $input[$end]) === false ) {
            return null;
        }
        return strtolower( substr( $input, $start, $end - $start ) );
    }


    /**
     * Scans a tag starting at $start (its first name character) and returns the
     * index at which it ends: ">" inside a quoted attribute value does not end
     * the tag, and a slash inside an unquoted value does not make it self-closing.
     * A "<" followed by a letter starts a new tag (Masterminds abandons the
     * current one — so "<br<br" is two tags); a "<" before anything else (e.g.
     * "</a>") is consumed as part of the current tag, as the parser does. A quoted
     * value is only entered
     * after "="; a bare "'"/'"' in attribute-name position is an ordinary name
     * character (matching the tokenizer), so it can't swallow the rest of the input.
     * $selfClosing is set only when the tag ends with a real tag-level "/>",
     * $attrs to the number of attributes (including adjacent quoted values without
     * separating whitespace), and $swallowed to the number of stray "<"
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
        $beforeAttribute = false;

        for( $i = $start; $i < $len; $i++ ) {
            $c = $input[$i];

            if( $state === 1 ) { if( $c === '"' ) { $state = 0; $beforeAttribute = true; } continue; }
            if( $state === 2 ) { if( $c === "'" ) { $state = 0; $beforeAttribute = true; } continue; }
            if( $state === 3 ) {                        // unquoted value: ">" ends it, "<"/"/" are literal
                if( $c === '>' ) { return $i; }
                if( $c === '<' ) { $swallowed++; continue; }
                if( strpos(self::WHITESPACE, $c) !== false ) {
                    $state = 0;
                    $beforeAttribute = true;
                }
                continue;
            }
            if( $state === 4 ) {                        // just saw "=", a value is about to start
                if( strpos(self::WHITESPACE, $c) !== false ) { continue; }
                if( $c === '"' ) { $state = 1; }
                elseif( $c === "'" ) { $state = 2; }
                elseif( $c === '>' ) { return $i; }
                else { if( $c === '<' ) { $swallowed++; } $state = 3; }
                $beforeAttribute = false;
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
            if( strpos(self::WHITESPACE, $c) !== false || $c === '/' ) {
                $beforeAttribute = true;
                $prevSlash = $c === '/';
                continue;
            }
            if( $beforeAttribute && $c !== '=' ) {
                $attrs++;
                // Stop scanning an attribute flood as soon as this tag alone
                // exceeds the budget. consumeTag() then rejects the input.
                if( $attrs * $attrs > self::MAX_ATTR_WORK ) {
                    return $i;
                }
            }
            $beforeAttribute = false;
            if( $c === '=' ) {
                $state = 4;
            }
            $prevSlash = false;
        }

        return $len;
    }
}
