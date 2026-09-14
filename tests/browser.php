<?php

// Generate a self-contained browser check: php tests/browser.php > /tmp/sanitizer-browser.html
require __DIR__ . '/../vendor/autoload.php';

$backends = [\Aimeos\Sanitizer\LegacyBackend::class];
if( class_exists('Dom\\HTMLDocument') ) {
    $backends[] = \Aimeos\Sanitizer\NativeBackend::class;
}
$cases = [];
$imageCases = [];
foreach( $backends as $backend ) {
    foreach( require __DIR__ . '/fixtures/security.php' as $name => $input ) {
        foreach( [false, true] as $strict ) {
            $cases[] = ['name' => $backend . ' ' . $name . ($strict ? ' strict' : ''), 'html' => $backend::sanitize($input, [], $strict)];
        }
    }
    foreach( ['/\\untrusted.invalid/a.js', "/\t/untrusted.invalid/a.js", '/safe/../a.js', '/safe/%2e%2e/a.js', '/SAFE/a.js'] as $url ) {
        $prefix = str_starts_with($url, '/safe/') || str_starts_with($url, '/SAFE/') ? '/safe/' : '/';
        $cases[] = ['name' => $backend . ' URL ' . $url, 'html' => $backend::sanitize('<script src="' . $url . '"></script>', ['script' => [$prefix]])];
    }
    foreach( ['', ' href="https://untrusted.invalid/a.js"', ' xlink:href="https://untrusted.invalid/a.js"'] as $href ) {
        $cases[] = [
            'name' => $backend . ' SVG script' . $href,
            'html' => $backend::sanitize('<svg><script src="/approved.js"' . $href . '>confirm(22)</script></svg>', ['svg' => true, 'script' => ['/approved.js']]),
            'allowed' => ['svg'],
        ];
    }
    // Retain the legacy parser-differential guards when trusted exceptions are
    // enabled, including raw-text endings and mixed foreign/HTML content.
    foreach( [
        ['<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>', ['noscript' => true]],
        ['<style></style/><img src=x onerror=alert(1)>', ['style' => true]],
        ['<style></style foo><img src=x onerror=alert(1)>', ['style' => true]],
        ['<svg><foreignObject><style></style/><img src=x onerror=alert(1)></foreignObject></svg>', ['svg' => true, 'style' => true]],
        ['<svg><title title="&quot;&lt;img src=x onerror=confirm(1)&gt;">tip</title></svg>', ['svg' => true]],
    ] as [$input, $allow] ) {
        $cases[] = ['name' => $backend . ' exception ' . $input, 'html' => $backend::sanitize($input, $allow), 'allowed' => array_keys($allow)];
    }
    foreach( require __DIR__ . '/fixtures/srcset.php' as $name => $case ) {
        $value = preg_replace_callback('/[\x00-\x1f]/', fn($m) => '&#' . ord($m[0]) . ';', htmlspecialchars($case['value'], ENT_QUOTES, 'UTF-8'));
        $input = '<img srcset="' . $value . '">';
        $test = ['name' => $backend . ' srcset ' . $name, 'html' => $backend::sanitize($input, []), 'blockedSrcset' => $case['blocked']];
        $cases[] = $test;
        if( $case['renders'] ?? false ) {
            $imageCases[] = $test;
        }
    }
    foreach( require __DIR__ . '/fixtures/ping.php' as $name => $case ) {
        $value = preg_replace_callback('/[\x00-\x1f]/', fn($m) => '&#' . ord($m[0]) . ';', htmlspecialchars($case['value'], ENT_QUOTES, 'UTF-8'));
        foreach( ['a', 'area'] as $tag ) {
            $input = '<' . $tag . ' href="/" ping="' . $value . '">' . ($tag === 'a' ? 'click</a>' : '');
            $cases[] = [
                'name' => $backend . ' ' . $tag . ' ping ' . $name,
                'html' => $backend::sanitize($input, []),
                'expected' => ['tag' => $tag, 'present' => true, 'attributes' => ['ping' => $case['blocked'] ? null : $case['value']]],
            ];
        }
    }
    foreach( require __DIR__ . '/fixtures/meta-refresh.php' as $name => $case ) {
        $value = preg_replace_callback('/[\x00-\x1f]/', fn($m) => '&#' . ord($m[0]) . ';', htmlspecialchars($case['content'], ENT_QUOTES, 'UTF-8'));
        $input = '<meta http-equiv="ReFrEsH" content="' . $value . '">';
        foreach( [true, ['https://trusted.example/safe/']] as $allow ) {
            $cases[] = [
                'name' => $backend . ' meta refresh ' . $name . ($allow === true ? ' unrestricted' : ' prefix'),
                'html' => $backend::sanitize($input, ['meta' => $allow]),
                'allowed' => ['meta'],
                'expected' => ['tag' => 'meta', 'present' => $allow === true || $case['allowed'],
                    'attributes' => ['content' => ($case['blocked'] ?? false) ? null : $case['content']]],
            ];
        }
    }
    // Cover every scalar URL attribute, including those outside href/src.
    foreach( ['href', 'src', 'xlink:href', 'formaction', 'action', 'background', 'poster', 'data', 'cite', 'longdesc'] as $attribute ) {
        foreach( ['javascript:confirm(1)', 'file:///tmp/test', 'data:text/html,anything', '/safe/path'] as $value ) {
            $cases[] = [
                'name' => $backend . ' scalar URL ' . $attribute . ' ' . $value,
                'html' => $backend::sanitize('<a ' . $attribute . '="' . $value . '">click</a>', []),
                'expected' => ['tag' => 'a', 'present' => true, 'attributes' => [$attribute => $value === '/safe/path' ? $value : null]],
            ];
        }
    }
}
foreach( require __DIR__ . '/fixtures/srcset.php' as $name => $case ) {
    if( $case['renders'] ?? false ) {
        $imageCases[] = ['name' => 'image loading control ' . $name, 'html' => '<img srcset="' . $case['value'] . '">'];
    }
}

// Exercise the public entry points too: backend-only checks bypass Limits.
$publicInputs = (require __DIR__ . '/fixtures/security.php') + [
    'tag-name-prefix' => '<script:x><img src=x onerror=confirm(33)></script:x><p>ok</p>',
    'false-text-close' => '<style></stylex><!--</style><img src=x onerror=confirm(33)>',
    'script-double-escape' => '<script><!--<script></script><!--</script><img src=x onerror=confirm(33)>',
    'invalid-utf8-tag' => "<\xffdiv><img src=x onerror=confirm(33)></div>",
    'invalid-utf8-attribute' => '<a href="java' . "\xff" . 'script:confirm(33)">ok</a>',
    'rel-token-boundaries' => '<a target="_blank" href="/" rel="not-noopener noreferrer-extra" onclick=confirm(33)>ok</a>',
    'rel-whitespace' => '<a target="_blank" href="/" rel="&#12;ugc&#9;noopener&#12;">ok</a>',
];
foreach( $publicInputs as $name => $input ) {
    foreach( ['html', 'strict'] as $method ) {
        $output = \Aimeos\Sanitizer\Sane::$method($input);
        $cases[] = ['name' => 'Sane::' . $method . ' ' . $name, 'html' => $output];
        $cases[] = ['name' => 'Sane::' . $method . ' repeated ' . $name, 'html' => \Aimeos\Sanitizer\Sane::$method($output)];
    }
}
?>
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; frame-src about:; img-src data:">
<title>Sanitizer browser reparse check</title>
<pre id="result">Running</pre>
<script>
const cases = <?= json_encode($cases, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR) ?>;
const imageCases = <?= json_encode($imageCases, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR) ?>;
const failures = [];
const forbidden = ['script', 'style', 'iframe', 'object', 'embed', 'svg', 'math', 'template', 'noscript', 'base', 'meta', 'link'];
const scalarUrls = ['href', 'src', 'xlink:href', 'formaction', 'action', 'background', 'poster', 'data', 'cite', 'longdesc'];
function checkUrl(value, name) {
    try {
        const url = new URL(value, 'https://sanitizer.example/');
        if (['javascript:', 'vbscript:', 'file:', 'filesystem:', 'blob:'].includes(url.protocol)
            || (url.protocol === 'data:' && !/^data:\s*image\/(?:png|jpeg|gif|webp)\s*[;,]/i.test(value))) {
            failures.push(name + ': blocked URL');
        }
    } catch (_) { /* An invalid URL cannot execute a script scheme. */ }
}
for (const test of cases) {
    // Exercise document parsing and the fragment parser used by innerHTML.
    const documentResult = new DOMParser().parseFromString(test.html, 'text/html');
    const fragmentResult = document.createElement('div');
    fragmentResult.innerHTML = test.html;
    for (const root of [documentResult, fragmentResult]) {
        const selector = forbidden.filter(tag => !(test.allowed || []).includes(tag)).join(',');
        if (root.querySelector(selector)) failures.push(test.name + ': active element');
        if (test.blockedSrcset && root.querySelector('[srcset]')) failures.push(test.name + ': blocked srcset survived');
        if (test.expected) {
            const element = root.querySelector(test.expected.tag);
            if (Boolean(element) !== test.expected.present) failures.push(test.name + ': incorrect element presence');
            if (element) {
                for (const [name, value] of Object.entries(test.expected.attributes)) {
                    // HTML reparsing normalizes literal CR and CRLF to LF.
                    const expected = value === null ? null : value.replace(/\r\n?/g, '\n');
                    if (element.getAttribute(name) !== expected) failures.push(test.name + ': incorrect ' + name);
                }
            }
        }
        for (const element of root.querySelectorAll('*')) {
            if (['a', 'area', 'form'].includes(element.localName)
                && !['', '_self', '_parent', '_top'].includes((element.getAttribute('target') || '').toLowerCase())) {
                const rel = new Set((element.getAttribute('rel') || '').toLowerCase().split(/[ \t\r\n\f]+/));
                if (!rel.has('noopener') || !rel.has('noreferrer')) failures.push(test.name + ': missing opener protection');
            }
            for (const attr of element.attributes) {
                if (/^on/i.test(attr.name)) failures.push(test.name + ': event attribute');
                if (scalarUrls.includes(attr.name) || scalarUrls.includes(attr.localName)) checkUrl(attr.value, test.name);
                if (attr.localName === 'ping') {
                    for (const value of attr.value.split(/[ \t\r\n\f]+/)) checkUrl(value, test.name);
                }
            }
        }
    }
}

// Run real document parsing in isolated frames. CSP permits inline execution
// but blocks external resources; the sandbox keeps each frame off our origin.
// Unsanitized positive controls prove that script/event execution is observable.
const controls = [
    {name: 'inline execution control', html: '<script>confirm(1)<\/script>', executes: true},
    {name: 'SVG execution control', html: '<svg onload="confirm(1)"></svg>', executes: true},
];
function execute(test) {
    return new Promise(resolve => {
        const frame = document.createElement('iframe');
        frame.sandbox = 'allow-scripts';
        let timeout;
        function finish(error) {
            if (error) failures.push(test.name + ': ' + error);
            clearTimeout(timeout);
            window.removeEventListener('message', receive);
            frame.remove();
            resolve();
        }
        function receive(event) {
            if (event.source !== frame.contentWindow || event.data?.check !== 'sanitizer') return;
            finish(event.data.executed === Boolean(test.executes) ? '' : 'unexpected execution result');
        }
        window.addEventListener('message', receive);
        timeout = setTimeout(() => finish('execution check timed out'), 3000);
        frame.srcdoc = '<!doctype html><meta charset="utf-8"><script>'
            + 'window.sanitizerExecuted = false;'
            + 'window.confirm = window.alert = window.prompt = () => {window.sanitizerExecuted = true;};'
            + 'addEventListener("load", () => setTimeout(() => parent.postMessage({check:"sanitizer", executed:Boolean(window.sanitizerExecuted)}, "*"), 50));'
            + '<\/script>' + test.html;
        document.body.append(frame);
    });
}
function checkImage(test) {
    return new Promise(resolve => {
        const container = document.createElement('div');
        container.innerHTML = test.html;
        const img = container.querySelector('img');
        let timeout;
        function finish(error) {
            if (error) failures.push(test.name + ': ' + error);
            clearTimeout(timeout);
            container.remove();
            resolve();
        }
        if (!img?.hasAttribute('srcset')) {
            finish('srcset missing');
            return;
        }
        timeout = setTimeout(() => finish('image loading timed out'), 3000);
        document.body.append(container);
        img.decode().then(() => finish(img.naturalWidth === 1 && img.naturalHeight === 1 ? '' : 'incorrect image dimensions'))
            .catch(() => finish('image failed to load'));
    });
}
async function runChecks() {
    // Bound live frames so growing the corpus does not exhaust renderer capacity
    // and time out positive controls before their documents can start loading.
    const executionCases = [...cases, ...controls];
    for (let offset = 0; offset < executionCases.length; offset += 8) {
        await Promise.all(executionCases.slice(offset, offset + 8).map(execute));
    }
    await Promise.all(imageCases.map(checkImage));
    document.getElementById('result').textContent = JSON.stringify({passed: failures.length === 0, cases: cases.length, executionControls: controls.length, imageChecks: imageCases.length, failures});
}
runChecks();
</script>
</html>
