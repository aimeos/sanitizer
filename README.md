# Aimeos Sanitizer

Aimeos Sanitizer removes unsafe content from HTML fragments. It supports PHP
7.1 and later and offers two profiles: a strict profile for untrusted rich text
and a broader profile for applications that need backward compatibility.

## Quick start

Install the package:

```bash
composer require aimeos/sanitizer
```

Sanitize user-supplied rich text with the strict profile:

```php
use Aimeos\Sanitizer\Sane;

$input = '<p id="appConfig">Hello <strong>world</strong></p>'
    . '<script>alert(1)</script>';

$html = Sane::strict($input);

// <p>Hello <strong>world</strong></p>
```

## Which profile should I use?

| Method | Use it for | How it works |
| --- | --- | --- |
| `Sane::strict($input)` | User-supplied rich text | Keeps only known-safe elements and attributes |
| `Sane::html($input, $allow)` | Existing applications that need broader HTML support | Keeps content unless a rule blocks it |

Use `Sane::strict()` for content you do not control. The optional exceptions in
`Sane::html()` deliberately allow more powerful HTML and are only suitable for
trusted content.

## Strict profile

The strict profile uses a fixed allow-list. Callers cannot enable scripts,
embedded content or other executable elements.

### What it keeps

- Common text formatting, headings, lists, tables, links and images
- The global attributes `title`, `lang`, `dir` and `aria-label`
- HTTP(S), `mailto:`, `tel:` and relative URLs on links
- HTTP(S) and relative URLs on other supported elements
- Raster `data:` images on `<img src>`

Element-specific attributes are allowed only where they are appropriate. The
exact lists are defined in `Policy::STRICT_ELEMENTS`,
`Policy::STRICT_GLOBAL_ATTRS` and `Policy::STRICT_ATTRS`.

### What it removes

- Unknown elements and all of their contents
- Scripts and other executable content
- SVG, MathML, templates, forms, custom elements and embedded content
- `id`, `name`, `class`, `data-*`, `is`, event-handler, inline-style and
  framework-directive attributes
- Unknown URL schemes, data URLs on links and all `srcset` attributes

Removing IDs and names prevents content from creating named DOM properties. It
also means that in-content anchor targets are removed.

## Permissive compatibility profile

`Sane::html()` preserves a wider range of elements and attributes while removing
known-dangerous content:

```php
use Aimeos\Sanitizer\Sane;

$input = '<svg><circle r="40"/></svg>'
    . '<script>alert(1)</script>'
    . '<a href="javascript:alert(2)" style="color:red"'
    . ' onclick="alert(3)">Click me</a>'
    . '<img src="data:image/png;base64,...">';

echo Sane::html($input);

// <a>Click me</a><img src="data:image/png;base64,...">
```

### What it removes by default

- Comments, event handlers and style attributes
- The URL schemes `javascript:`, `vbscript:`, `file:`, `filesystem:` and
  `blob:`
- Selected IDs and names that could shadow global browser objects
- Scripts in SVG or MathML, including scripts at HTML integration points
- Script-capable SVG animation and handler elements, even when SVG is enabled

The following elements are blocked:

`applet`, `base`, `embed`, `form`, `frame`, `iframe`, `link`, `math`, `meta`,
`noembed`, `noframes`, `noscript`, `object`, `plaintext`, `portal`, `script`,
`style`, `svg`, `template` and `xmp`.

Application-specific names, attributes and URL schemes not listed above remain
possible in this profile.

### URL and image handling

Raster data URLs are accepted only for `image/png`, `image/jpeg`, `image/gif`
and `image/webp`. The sanitizer checks the declared MIME type, not the image
bytes.

For attributes containing multiple URLs:

- Every `srcset` candidate is checked. One blocked candidate removes the entire
  attribute. Commas inside URLs and raster data images are preserved; descriptor
  syntax and image selection are left to the browser.
- Every URL in a `ping` attribute is checked. One blocked URL removes the entire
  attribute. Values are separated on HTML ASCII whitespace, so commas remain
  part of a URL.

## Allowing trusted elements

The second argument to `Sane::html()` can allow an otherwise blocked element.
For example, this permits YouTube embed URLs under a specific path:

```php
$html = Sane::html($input, [
    'iframe' => ['https://www.youtube.com/embed/'],
]);
```

| Exception value | Result |
| --- | --- |
| A list of URL prefixes | Allows the element only when its URL matches a prefix |
| `true` | Allows the element without a URL restriction |
| `false` or an empty list | Keeps the element blocked |

> **Warning:** `true` can retain external scripts and the executable effects of
> allowed `<style>` content. Use it only with fully trusted content. Event
> handlers, inline style attributes, blocked URL schemes and inline scripts are
> still removed.

### How URL-prefix matching works

- A match must end at a path, query or fragment boundary. A prefix such as
  `/embed/` cannot accidentally match `/embed-malicious/`.
- Schemes and hosts are compared case-insensitively. Paths, queries and
  fragments are case-sensitive. Default HTTP(S) ports are normalized.
- Prefixes can use HTTP(S) URLs with ASCII hosts, protocol-relative URLs or
  relative paths. Use punycode for internationalized domain names.
- A relative prefix cannot allow an absolute or protocol-relative URL.
- URLs containing raw whitespace, control characters, backslashes, credentials
  or literal or percent-encoded dot path segments are rejected.
- Relative paths resolve against the consuming document's base URL. Redirects
  and downloaded resource contents are not inspected.

For `meta http-equiv="refresh"`, the prefix is compared with the extracted
redirect URL. Invalid refresh values and reloads without a URL cannot match an
exception. Other metadata is compared using its `content` value.

### Restrictions on embedded content

Allowed embedding elements receive a restricted set of attributes. Iframes:

- Have `srcdoc` removed
- Receive `sandbox="allow-scripts allow-popups"`
- Have unsupported features removed from their `allow` attribute

The elements `frame`, `embed` and `object` cannot be sandboxed in the same way.
Allowed template contents are sanitized on the legacy backend but discarded on
the native backend because its DOM API cannot access them.

## Output and safety rules

Both profiles accept UTF-8 and return a UTF-8 HTML fragment representing the
contents of an HTML element.

- Malformed UTF-8 is rejected before parsing and returns an empty string.
- Input charset declarations cannot change the parser encoding. Serve the result
  inside a UTF-8 HTML document.
- An empty string can mean that the input was rejected or that sanitization
  removed everything.
- The result is safe only as HTML content. It is not encoded for an HTML
  attribute, JavaScript, CSS or another parsing context.
- Do not later reinterpret retained text or attribute values as HTML.

PHP 8.4+ uses the native HTML5 parser. Older PHP versions use Masterminds HTML5.
Both use the same security policy, but malformed HTML repair and serialization
can differ. The legacy backend uses HTML5 serialization to preserve checked URL
values such as IPv6 hosts, which is slower for large fragments.

## Resource limits

Hostile or excessively complex input is rejected with an empty string. The main
limits are:

| Resource | Limit |
| --- | ---: |
| Input size | 4 MiB |
| Element nesting | 256 elements |
| Estimated nodes | 50,000 |
| Estimated attributes | 100,000 |
| Copied formatting start-tag data | 4 MiB |
| Legacy parsing errors | 2,048 |

Excessive attribute processing or malformed-markup work is rejected as well.

<details>
<summary><strong>Advanced parser safeguards</strong></summary>

### Before and after parsing

Before parsing, a lightweight scan estimates nodes, attributes, nesting and the
extra nodes a parser may create while repairing formatting. These estimates are
intentionally conservative. Only correctly nested, explicit formatting end tags
reduce the estimated repair cost.

After parsing, an iterative DOM scan checks the actual depth, node types,
attributes and attribute-processing cost. Parser repairs that exceed the limits
are rejected. Descendants of removed elements are not filtered separately.

Link `rel` tokens and iframe permission directives are processed without large
temporary token arrays.

### Legacy parser behavior

The legacy backend counts scanner, tokenizer and tree-repair errors together.
It rejects the document if their combined count exceeds 2,048. Illegal code
points are counted before diagnostic data is allocated, and unused error
messages and source positions are skipped. As a result, malformed input can be
rejected by the legacy backend even when the native backend accepts it.

The scanner follows HTML whitespace rules. The legacy tokenizer preserves form
feeds inside quoted values, matching the native parser and allowing repeated
sanitization of values containing `&#12;`. Form feeds between attributes remain
valid whitespace. A literal less-than sign in text, such as `x <= 2`, is
preserved as `&lt;`.

### Ambiguous markup

Input is rejected before parsing when the two backends would disagree about its
boundaries. This includes:

- Declarations or CDATA containing nested markup
- Ambiguous declaration endings
- Tag-name characters interpreted differently by the parsers
- Malformed raw-text closing tags
- Script double escapes
- Nested markup in foreign raw-text or RCDATA elements

Use explicit closing tags and escape literal angle brackets in text. Complete
tag names, including colons and underscores, are preserved when both parsers
agree on them.

</details>

## Development and validation

### Unit tests and static analysis

```bash
XDEBUG_MODE=off php vendor/bin/phpunit
php vendor/bin/phpstan analyze --no-progress --debug
```

Run PHPUnit across the supported PHP versions, including PHP 7.1 and PHP 8.4+.
PHP 7.1 development environments use Composer 2.2 LTS and PHPUnit 7.5.
Cross-version assertion polyfills keep the same security suite available there.
Run static analysis on a current PHP version.

When the native API is available, the security suite runs its shared corpus
directly through both backends. Functional tests verify sanitization and limit
handling without relying on machine-speed thresholds.

### Browser checks

```bash
php tests/browser.php > /tmp/sanitizer-browser.html
```

Open the generated file in a browser. It reports `passed: true` when all cases
pass. The checks cover document and `innerHTML` reparsing and execution in
sandboxed frames. Unsanitized positive controls confirm that execution can be
detected. The Content Security Policy blocks external resources while allowing
the inline code and raster data images required by the checks.

### Performance benchmark

```bash
timeout 30s env XDEBUG_MODE=off php -d memory_limit=64M tests/benchmark.php
```

Run the benchmark on an idle machine for each PHP version. It reports runtime
settings, median timings and growth across input sizes. Compare results on the
same machine and investigate superlinear growth before changing the 30-second
limit.

These checks validate this package. They do not audit how downstream
applications use the sanitized output.
