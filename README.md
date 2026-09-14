# Aimeos Sanitizer

HTML fragment sanitization for PHP 7.1+. PHP 8.4+ uses the native HTML5 parser;
older PHP versions use Masterminds HTML5. Both backends share the security policy.

## Installation

```bash
composer require aimeos/sanitizer
```

## Untrusted rich text

Use the fixed strict profile for user-supplied rich text:

```php
use Aimeos\Sanitizer\Sane;

$html = Sane::strict('<p id="appConfig">Hello <strong>world</strong></p><script>alert(1)</script>');
// <p>Hello <strong>world</strong></p>
```

Strict mode preserves common text formatting, headings, lists, tables, links and
images. Its element and per-element attribute allow-lists are defined in
`Policy::STRICT_ELEMENTS`, `Policy::STRICT_GLOBAL_ATTRS` and `Policy::STRICT_ATTRS`.
Unknown elements are removed together with their contents. Executable content,
SVG/MathML, templates, forms, custom elements and embedding elements cannot be
opted back in.

All `id`, `name`, `class`, `data-*`, `is`, event handlers, inline styles and framework
directives are removed. Removing IDs and names prevents content from creating
named DOM properties, but also removes in-content anchor targets. Global attributes
are limited to `title`, `lang`, `dir` and `aria-label`.

Links accept HTTP(S), `mailto:`, `tel:` and relative URLs. Other URL attributes
accept HTTP(S) and relative URLs; raster `data:` images are additionally accepted
on `<img src>`. Unknown schemes and data URLs on links are removed. Responsive
`srcset` attributes are omitted in this profile.

## Permissive compatibility profile

The existing API preserves other elements and attributes unless specifically
blocked. Use this profile when the consuming application needs that compatibility:

```php
$input = '<svg><circle r="40"/></svg><script>alert(1)</script>'
    . '<a href="javascript:alert(2)" style="color:red" onclick="alert(3)">Click me</a>'
    . '<img src="data:image/png;base64,...">';

echo Sane::html($input);
// <a>Click me</a><img src="data:image/png;base64,...">
```

The default blocked elements are `applet`, `base`, `embed`, `form`, `frame`,
`iframe`, `link`, `math`, `meta`, `noembed`, `noframes`, `noscript`, `object`,
`plaintext`, `portal`, `script`, `style`, `svg`, `template` and `xmp`.
Comments, event handlers and style attributes are removed. Script-bearing SVG
animation/handler elements remain blocked even when SVG is enabled. Scripts in
SVG/MathML contexts (including their HTML integration points) are always removed.

URL attributes reject `javascript:`, `vbscript:`, `file:`, `filesystem:` and `blob:`.
Data URLs are accepted only for `image/png`, `image/jpeg`, `image/gif` and
`image/webp`; this checks the declared MIME type, not the image bytes. Other schemes
are preserved by this profile. Selected global-object IDs/names are removed;
application-specific names and attributes remain possible.

`srcset` candidates use HTML URL boundaries, preserving commas inside URLs and
raster data images. A blocked candidate removes the whole attribute. Descriptor
syntax and image selection remain the browser's responsibility.
`ping` values are split on HTML ASCII whitespace and every URL is checked; a
blocked URL removes the whole attribute. Commas remain part of each URL.

### Trusted exceptions

The second argument opts blocked elements back in:

```php
$html = Sane::html($input, [
    'iframe' => ['https://www.youtube.com/embed/'],
]);
```

- A URL-prefix list requires an accepted URL and a path/query/fragment boundary.
  Scheme and host are case-insensitive, default HTTP(S) ports are normalized, and
  paths, queries and fragments are case-sensitive.
- For `meta http-equiv="refresh"`, prefixes match the extracted redirect URL.
  Invalid refresh syntax and reloads without an explicit URL cannot satisfy a
  prefix exception. Other metadata continues to match its `content` value.
- Prefixes support HTTP(S) URLs with ASCII hosts (use punycode for IDNs),
  protocol-relative URLs and relative paths. Relative prefixes cannot authorize
  absolute or protocol-relative candidates. Raw whitespace/control characters,
  backslashes, credentials and literal or percent-encoded dot path segments are
  rejected. Use normalized URLs. Relative paths resolve against the consuming
  document's base URL; redirects and fetched resource contents are not inspected.
- `true` allows the element without URL-prefix restrictions. Event handlers,
  inline style attributes and blocked URL schemes are still removed. Inline scripts
  are dropped, but external scripts and allowed `<style>` contents retain their
  executable effects. These are trusted-content exceptions, not suitable for
  untrusted rich text.
- `false` or an empty prefix list keeps an element blocked.

Embedding exceptions receive a restricted attribute list. Iframes have `srcdoc`
removed, receive `sandbox="allow-scripts allow-popups"`, and have their `allow`
features filtered. `frame`, `embed` and `object` cannot be sandboxed this way.
An allowed template has its contents sanitized on the legacy backend and discarded
on the native backend, whose DOM API cannot access that content.

## Output and resource limits

Both APIs accept UTF-8 and return UTF-8 HTML fragments for an HTML element's content.
Malformed UTF-8 returns an empty string before markup scanning or parsing, so
discarded bytes cannot expose markup that bypasses the resource checks.
Input charset declarations cannot change the parser encoding. Serve the output in
a UTF-8 HTML document. These APIs are not
encoders for attributes, JavaScript, CSS or arbitrary parsing contexts. Do not
reinterpret retained attribute/text values as HTML later in the application.
Serialization and malformed-markup repair can differ between backends. The legacy
backend uses HTML5 serialization to preserve URL values, including IPv6 hosts;
this is slower than libxml serialization on large fragments.
The legacy parser counts scanner, tokenizer and tree-repair errors together and
rejects a document after 2,048 errors. Illegal code points are counted before the
scanner allocates its diagnostics, keeping that allocation bounded. Tokenizer and
tree-repair errors skip unused messages and source-position calculations, which
would otherwise repeatedly scan the input. This additional
legacy limit can produce empty output for malformed content the native parser accepts.

Input over 4 MiB, excessive nesting (256 elements), more than 50,000 estimated nodes,
more than 100,000 estimated attributes, or excessive attribute/malformed-markup work
returns an empty string. The pre-scan counts elements, text runs, comments and
declarations before the parser allocates them. Markup boundaries can conservatively
split text runs that a parser merges.
The estimates also charge possible copies of active formatting elements, including
their attributes, with a separate 4 MiB budget for copied start-tag bytes. This
prevents malformed formatting from expanding into a much larger DOM before it can
be checked. Estimates deliberately overcount: only correctly nested explicit
formatting end tags cancel the corresponding future copy cost.
An iterative DOM traversal checks actual depth, all node types, total attributes
and attribute cost before filtering, with an allowance for document wrappers.
Parser repairs that exceed the DOM limits are rejected too. Filtering skips the
descendants of removed elements.
Link `rel` tokens and iframe permission directives are processed without building
large token arrays, preserving existing values while limiting temporary memory.
The scan uses HTML whitespace rules, so other control characters cannot disguise
unquoted attribute values as quoted ones. The legacy tokenizer preserves form feeds
inside quoted values, matching native parsing and allowing repeated sanitization
of attributes containing `&#12;`. Form feeds between attributes remain valid
whitespace. Literal less-than signs in ordinary text, such as `x <= 2`, are
preserved as `&lt;` instead of being discarded by the legacy tokenizer.
Declarations/CDATA containing nested markup and
ambiguous declaration endings are rejected before parsing because the two parsers
interpret them differently. The scan preserves complete tag names, including
colons and underscores, and rejects name characters on which the parsers disagree.
Malformed raw-text closing tags, script double escapes, and nested markup in
foreign raw-text/RCDATA elements are also rejected when their boundaries are
ambiguous. Use explicit closing tags and escape literal angle brackets in text.
Empty output may also mean all content was removed.

## Validation

```bash
XDEBUG_MODE=off php vendor/bin/phpunit
php vendor/bin/phpstan analyze --no-progress --debug
php tests/browser.php > /tmp/sanitizer-browser.html
timeout 30s env XDEBUG_MODE=off php -d memory_limit=64M tests/benchmark.php
```

Run PHPUnit across PHP 7.1+ and PHP 8.4+. PHP 7.1 development installs use
Composer 2.2 LTS and PHPUnit 7.5; the cross-version assertion polyfills keep the
same security suite available there. Static analysis runs on a current PHP version.
The security regression suite also runs its shared corpus directly through both
backends when the native API is available. Open the generated browser file to
check document and `innerHTML` reparsing and execution in sandboxed frames; it
reports `passed: true` when all cases pass. Unsanitized positive controls verify
that execution can be detected. Its CSP blocks external resources while allowing
inline code and raster data images used to verify `srcset` loading.
Functional tests assert sanitization and budget rejection without machine-speed
thresholds. Run the benchmark separately on an idle worker under each PHP version;
it reports runtime settings, median timings and growth across input sizes. The
30-second process limit bounds the whole benchmark run. Compare results on the
same machine and investigate superlinear growth before adjusting that budget.
These focused checks are not an audit of downstream application sinks.
