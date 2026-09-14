<?php

$pingCases = [
    'empty list' => ['value' => '', 'blocked' => false],
    'HTTP and relative URLs' => ['value' => 'https://example.com/ping /ping //example.org/ping', 'blocked' => false],
    'commas are URL data' => ['value' => '/ping,javascript:part', 'blocked' => false],
    'scheme text in path' => ['value' => '/ping https://example.com/javascript:part', 'blocked' => false],
    'non-HTML whitespace is URL data' => ['value' => "/ping\u{00a0}javascript:part", 'blocked' => false],
    'first blocked URL' => ['value' => 'javascript:confirm(1) /ping', 'blocked' => true],
    'last blocked URL' => ['value' => '/ping https://example.com/ping javascript:confirm(1)', 'blocked' => true],
    'blocked HTML data URL' => ['value' => '/ping data:text/html,anything', 'blocked' => true],
    'blocked SVG data URL' => ['value' => '/ping data:image/svg+xml,anything', 'blocked' => true],
    'blocked file URL' => ['value' => '/ping file:///tmp/test', 'blocked' => true],
    'blocked blob URL' => ['value' => '/ping blob:https://example.com/id', 'blocked' => true],
    'control inside scheme' => ['value' => "/ping java\x0bscript:confirm(1)", 'blocked' => true],
    'ASCII whitespace only' => ['value' => " \t\r\n\f", 'blocked' => false],
];
foreach( str_split(" \t\r\n\f") as $space ) {
    $pingCases['separator ' . ord($space)] = ['value' => $space . '/ping' . $space . 'VbScRiPt:bad' . $space, 'blocked' => true];
}
return $pingCases;
