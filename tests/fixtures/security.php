<?php

// Shared by the PHP regression tests and the browser reparse check.
return [
    'encoding' => '<meta charset="iso-2022-jp">' . "\x1b\$B" . 'a<svg/onload=confirm(11)>a' . "\x1b(B",
    'attribute-boundaries' => '<p title="&quot;&lt;img src=x onerror=confirm(1)&gt;&amp;">&lt;script&gt; &amp;lt;img&amp;gt; Grüße</p>',
    'script' => '<script>window.sanitizerExecuted = true</script><p>ok</p>',
    'events' => '<img src=x onerror="window.sanitizerExecuted = true"><p onclick="alert(1)">ok</p>',
    'controls' => '<a href="java&#9;script:alert(1)">ok</a>',
    'quoted-form-feed' => "<div title=\"\f><img src=x onerror=confirm(55)></div>",
    'closed-quoted-form-feed' => "<p title=\"\f><img src=x onerror=confirm(55)>\" onclick=confirm(55)>ok</p>",
    'single-quoted-form-feed' => "<p title='\f><img src=x onerror=confirm(55)>' onclick=confirm(55)>ok</p>",
    'encoded-form-feed' => '<p title="&#12;&quot;&gt;&lt;img src=x onerror=confirm(55)&gt;" onclick=confirm(55)>ok</p>',
    'invalid-reference' => '<p>&notanentity;&lt;script&gt;</p><img src=x onerror=confirm(55)>',
    'literal-less-than' => '<p>x <= 2 <<img src=x onerror=confirm(55)></p>',
    'reference-before-less-than' => '&amp;&amp;< 2 &lt;<img src=x onerror=confirm(55)>',
    'cdata' => '<![CDATA[><img src=x onerror=alert(1)>]]><p>ok</p>',
    'noscript' => '<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript><p>ok</p>',
    'foreign' => '<svg><foreignObject><style></style/><img src=x onerror=alert(1)></foreignObject></svg><p>ok</p>',
    'math' => '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>"><p>ok</p>',
    'template' => '<template><svg><script>alert(1)</script></svg><img src=x onerror=alert(1)></template><p>ok</p>',
    'structural' => '<html><head><title>title</title></head><body onload="alert(1)"><p>ok</p></body></html>',
];
