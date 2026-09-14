<?php

// Long delays keep accepted redirects from navigating the browser test frames.
$safe = 'https://trusted.example/safe/page';
$refreshCases = [
    'standard URL' => ['content' => '3600;url=' . $safe, 'url' => $safe, 'allowed' => true],
    'quoted URL' => ['content' => '3600;URL="' . $safe . '"', 'url' => $safe, 'allowed' => true],
    'single-quoted URL' => ['content' => "3600; url='" . $safe . "'", 'url' => $safe, 'allowed' => true],
    'comma separator' => ['content' => '3600, ' . $safe, 'url' => $safe, 'allowed' => true],
    'whitespace separator' => ['content' => '3600 ' . $safe, 'url' => $safe, 'allowed' => true],
    'fractional delay' => ['content' => '3600.5;url=' . $safe, 'url' => $safe, 'allowed' => true],
    'unclosed quote' => ['content' => '3600;url="' . $safe, 'url' => $safe, 'allowed' => true],
    'trailing quoted text' => ['content' => '3600;url="' . $safe . '" ignored', 'url' => $safe, 'allowed' => true],
    'opposite quote is data' => ['content' => '3600;url="' . $safe . "'next\"", 'url' => $safe . "'next", 'allowed' => true],
    'greater-than is data' => ['content' => '3600;url=' . $safe . '>next', 'url' => $safe . '>next', 'allowed' => true],
    'untrusted host' => ['content' => '3600;url=https://untrusted.example/safe/page', 'url' => 'https://untrusted.example/safe/page', 'allowed' => false],
    'host suffix' => ['content' => '3600;url=https://trusted.example.evil/safe/page', 'url' => 'https://trusted.example.evil/safe/page', 'allowed' => false],
    'dot path' => ['content' => '3600;url=https://trusted.example/safe/../page', 'url' => 'https://trusted.example/safe/../page', 'allowed' => false],
    'case-sensitive path' => ['content' => '3600;url=https://trusted.example/SAFE/page', 'url' => 'https://trusted.example/SAFE/page', 'allowed' => false],
    'space inside URL' => ['content' => '3600;url="' . $safe . ' next"', 'url' => $safe . ' next', 'allowed' => false],
    'control inside URL' => ['content' => "3600;url=https://trusted.example/sa\tfe/page", 'url' => "https://trusted.example/sa\tfe/page", 'allowed' => false],
    'partial URL prefix' => ['content' => '3600;url ' . $safe, 'url' => 'url ' . $safe, 'allowed' => false],
    'missing delay' => ['content' => $safe, 'url' => null, 'allowed' => false],
    'missing delay before URL' => ['content' => ';url=' . $safe, 'url' => null, 'allowed' => false],
    'negative delay' => ['content' => '-3600;url=' . $safe, 'url' => null, 'allowed' => false],
    'missing separator' => ['content' => '3600url=' . $safe, 'url' => null, 'allowed' => false],
    'non-HTML whitespace separator' => ['content' => "3600\u{00a0}url=" . $safe, 'url' => null, 'allowed' => false],
    'reload only' => ['content' => '3600', 'url' => null, 'allowed' => false],
    'empty URL' => ['content' => '3600;url=', 'url' => '', 'allowed' => false],
    'empty content' => ['content' => '', 'url' => null, 'allowed' => false],
    'whitespace content' => ['content' => " \t\r\n\f", 'url' => null, 'allowed' => false],
    'blocked script' => ['content' => '0;url=javascript:confirm(1)', 'url' => 'javascript:confirm(1)', 'allowed' => false, 'blocked' => true],
    'blocked implicit URL' => ['content' => '0 javascript:confirm(1)', 'url' => 'javascript:confirm(1)', 'allowed' => false, 'blocked' => true],
    'blocked leading dot' => ['content' => '.5;url=vbscript:bad', 'url' => 'vbscript:bad', 'allowed' => false, 'blocked' => true],
    'blocked control in scheme' => ['content' => "0;url=java\x0bscript:confirm(1)", 'url' => "java\x0bscript:confirm(1)", 'allowed' => false, 'blocked' => true],
    'blocked quoted URL' => ['content' => "0;url='  javascript:confirm(1)'", 'url' => '  javascript:confirm(1)', 'allowed' => false, 'blocked' => true],
    'blocked HTML data URL' => ['content' => '0;url=data:text/html,anything', 'url' => 'data:text/html,anything', 'allowed' => false, 'blocked' => true],
];
foreach( str_split(" \t\r\n\f") as $space ) {
    $refreshCases['whitespace ' . ord($space)] = ['content' => $space . '3600' . $space . ';' . $space . 'uRl' . $space . '=' . $space . $safe, 'url' => $safe, 'allowed' => true];
}
return $refreshCases;
