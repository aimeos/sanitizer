<?php

// A real 1x1 PNG lets the browser check image loading as well as URL filtering.
$png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a6YQAAAAASUVORK5CYII=';
$percent = 'data:image/png,' . rawurlencode(base64_decode($png));
$base64 = 'data:image/png;base64,' . $png;

return [
    'percent-encoded PNG' => ['value' => $percent . ' 1x', 'blocked' => false, 'renders' => true],
    'base64 PNG' => ['value' => $base64 . ' 1x', 'blocked' => false, 'renders' => true],
    'mixed PNG candidates' => ['value' => $percent . ' 1x, ' . $base64 . ' 2x', 'blocked' => false],
    'commas inside URLs' => ['value' => '/image,a.png 480w, /image,b.png 800w', 'blocked' => false],
    'trailing URL comma' => ['value' => "/image,a.png,\t/image,b.png 2x", 'blocked' => false],
    'adjacent descriptors' => ['value' => 'safe.png 1x,https://example.com/a,b.png 2x', 'blocked' => false],
    'scheme text inside URL' => ['value' => 'https://example.com/a,javascript:part.png 1x', 'blocked' => false],
    'commas inside descriptors' => ['value' => 'safe.png (future, javascript:descriptor), next.png 2x', 'blocked' => false],
    'empty candidates' => ['value' => ", \t, safe.png 1x,,", 'blocked' => false],
    'first blocked URL' => ['value' => 'javascript:alert(1) 1x, safe.png 2x', 'blocked' => true],
    'blocked URL after trailing comma' => ['value' => 'safe.png, javascript:alert(1) 2x', 'blocked' => true],
    'blocked URL after descriptor' => ['value' => 'safe.png 1x,javascript:alert(1) 2x', 'blocked' => true],
    'blocked URL after empty candidates' => ['value' => "\t,\f javascript:alert(1)", 'blocked' => true],
    'HTML data URL' => ['value' => 'safe.png 1x, data:text/html,%3Cscript%3E 2x', 'blocked' => true],
    'SVG data URL' => ['value' => 'safe.png (x), data:image/svg+xml,%3Csvg%3E 2x', 'blocked' => true],
    'non-nesting descriptor parentheses' => ['value' => 'safe.png (nested(foo), javascript:alert(1) 2x', 'blocked' => true],
    'control inside scheme' => ['value' => "safe.png 1x,java\x0bscript:alert(1) 2x", 'blocked' => true],
    'control before scheme' => ['value' => "safe.png 1x,\x0bjavascript:alert(1) 2x", 'blocked' => true],
];
