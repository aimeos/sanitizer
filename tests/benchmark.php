<?php

// Run separately from PHPUnit on an idle worker with Xdebug disabled.
// timeout 30s env XDEBUG_MODE=off php -d memory_limit=64M tests/benchmark.php
require __DIR__ . '/../vendor/autoload.php';

use Aimeos\Sanitizer\Sane;

printf("PHP %s; memory_limit=%s; XDEBUG_MODE=%s; opcache.enable_cli=%s\n",
    PHP_VERSION, ini_get('memory_limit'), getenv('XDEBUG_MODE') ?: 'unset', ini_get('opcache.enable_cli'));
echo "Three runs per size; median milliseconds and growth from previous size.\n";

$cases = [
    'comments' => [[25000, 49998, 100000], fn($n) => str_repeat('<!-- c -->', $n) . '<p>ok</p>', [], false],
    'text and comments' => [[10000, 24999, 50000], fn($n) => str_repeat('x<!-- c -->', $n) . '<p>ok</p>', [], true],
    'bogus comments' => [[25000, 100000, 500000], fn($n) => str_repeat('<!x>', $n) . '<p>ok</p>', [], true],
    'formatting copies' => [[50, 200, 1000], function($n) {
        $input = '';
        for( $i = 0; $i < $n; $i++ ) {
            $input .= '<p><b title="' . $i . '">text</p>';
        }
        return $input;
    }, [], true],
    'total attributes' => [[2500, 5000, 40000], function($n) {
        $tag = '<br';
        for( $i = 0; $i < 20; $i++ ) {
            $tag .= ' a' . $i;
        }
        return str_repeat($tag . '>', $n) . '<p>ok</p>';
    }, [], true],
    'meta whitespace' => [[1000, 2500, 5000], fn($n) => str_repeat('<meta http-equiv="refresh" content="' . str_repeat(' ', 40) . '">', $n), ['meta' => true], false],
    'refresh URL whitespace' => [[500000, 1000000, 2000000], fn($n) => '<meta http-equiv="refresh" content="3600;url' . str_repeat(' ', $n) . '=https://trusted.example/safe/page">', ['meta' => ['https://trusted.example/safe/']], false],
    'ping URL tokens' => [[250000, 500000, 1000000], fn($n) => '<a href="/" ping="' . str_repeat('x ', $n) . 'javascript:confirm(1)">click</a>', [], false],
    'vertical-tab attributes' => [[5000, 10000, 20000], fn($n) => "<div a=\x0b\"><div " . implode(' ', array_map(fn($i) => 'a' . $i, range(0, $n - 1))) . '>ok</div></div>', [], true],
    'quoted form-feed' => [[5000, 10000, 20000], fn($n) => "<div title=\"\f><div " . implode(' ', array_map(fn($i) => 'a' . $i, range(0, $n - 1))) . '>ok</div></div>', [], true],
    'scanner diagnostics' => [[750000, 1500000, 3000000], fn($n) => str_repeat("\x01", $n), [], true],
    'invalid UTF-8 attributes' => [[5000, 10000, 20000], fn($n) => "<\xffdiv " . implode(' ', array_map(fn($i) => 'a' . $i, range(1, $n))) . '>ok</div>', [], true],
    'rel tokens' => [[500000, 1000000, 2000000], fn($n) => '<a target="_blank" rel="' . str_repeat('x ', $n) . '">ok</a>', [], true],
    'iframe origin tokens' => [[250000, 500000, 1000000], fn($n) => '<iframe src="/approved" allow="autoplay ' . str_repeat('x ', $n) . '; camera; fullscreen"></iframe>', ['iframe' => ['/approved']], false],
    'invalid references' => [[5000, 10000, 20000], fn($n) => str_repeat('&notanentity;', $n), [], true],
    'valid references' => [[5000, 10000, 20000], fn($n) => str_repeat('&amp;&lt;&gt;&quot;', $n), [], true],
    'removed branches' => [[1000, 2000, 4000], fn($n) => '<object>' . str_repeat('<span title="tip">discarded</span>', $n) . '</object><p>ok</p>', [], true],
    'srcset candidates' => [[1000, 2000, 4000], fn($n) => '<img srcset="' . str_repeat('data:image/png,%89PNG 1x, ', $n) . '">', [], false],
];

Sane::html('<p>warmup</p>');
foreach( $cases as $name => [$sizes, $makeInput, $allow, $strict] ) {
    $previous = null;
    foreach( $sizes as $size ) {
        $input = $makeInput($size);
        $samples = [];
        for( $run = 0; $run < 3; $run++ ) {
            $start = hrtime(true);
            $output = $strict ? Sane::strict($input) : Sane::html($input, $allow);
            $samples[] = (hrtime(true) - $start) / 1e6;
        }
        sort($samples);
        $median = $samples[1];
        printf("%-24s n=%6d bytes=%7d median=%9.3f ms growth=%5s output=%d\n",
            $name, $size, strlen($input), $median, $previous === null ? '-' : sprintf('%.2f', $median / $previous), strlen($output));
        $previous = $median;
    }
}
