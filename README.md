# Aimeos Sanitizer

Permissive sanitizer removing potentially dangerous content.

## Installation

```bash
composer req aimeos/sanitizer
```

## Usage

```php
$input = '
    <svg><circle cx="50" cy="50" r="40" /></svg>
    <script>alert(1)</script>
    <a href="javascript:alert(2)" style="color:red;" onclick="alert(3)">Click me</a>
    <img src="data:image/png;base64,..." />
';
echo \Aimeos\Sanitizer\Sane::html( $input );

// Output: <a>Click me</a><img>
```

## Specification

### HTML

Removes these potential dangerous content:

- Elements: 'embed', 'frame', 'iframe', 'object', 'script', 'svg'
- Attributes: All that can execute code
- URI schemes: 'javascript', 'data', 'vbscript', 'file', 'filesystem', 'blob'
- IDs and names: Names used for global JS objects