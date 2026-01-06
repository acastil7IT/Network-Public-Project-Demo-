<?php
// Vulnerable Test Application - FOR TESTING ONLY
// DO NOT USE IN PRODUCTION

session_start();

// Vulnerable SQL injection endpoint
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // Intentionally vulnerable - no sanitization
    $query = "SELECT * FROM users WHERE id = " . $id;
    echo "<h3>SQL Query (Vulnerable):</h3>";
    echo "<code>" . htmlspecialchars($query) . "</code><br><br>";
    echo "<p>This endpoint is vulnerable to SQL injection for testing purposes.</p>";
}

// Vulnerable XSS endpoint
if (isset($_GET['name'])) {
    $name = $_GET['name'];
    // Intentionally vulnerable - no sanitization
    echo "<h3>Hello " . $name . "!</h3>";
    echo "<p>This endpoint is vulnerable to XSS for testing purposes.</p>";
}

// Directory traversal vulnerability
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // Intentionally vulnerable - no path validation
    $content = file_get_contents($file);
    echo "<h3>File Content:</h3>";
    echo "<pre>" . htmlspecialchars($content) . "</pre>";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .warning { background: #ffebee; border: 1px solid #f44336; padding: 15px; margin: 20px 0; }
        .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-left: 4px solid #2196F3; }
        code { background: #f0f0f0; padding: 2px 4px; }
    </style>
</head>
<body>
    <h1>🚨 Vulnerable Test Application</h1>
    
    <div class="warning">
        <strong>WARNING:</strong> This application contains intentional security vulnerabilities for testing purposes only.
        Never deploy this in a production environment!
    </div>

    <h2>Available Test Endpoints:</h2>
    
    <div class="endpoint">
        <h3>1. SQL Injection Test</h3>
        <p>Test SQL injection vulnerabilities:</p>
        <code>?id=1 OR 1=1</code><br>
        <code>?id=1; DROP TABLE users--</code>
        <p><a href="?id=1">Try: ?id=1</a></p>
    </div>

    <div class="endpoint">
        <h3>2. Cross-Site Scripting (XSS) Test</h3>
        <p>Test XSS vulnerabilities:</p>
        <code>?name=&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
        <code>?name=&lt;img src=x onerror=alert('XSS')&gt;</code>
        <p><a href="?name=TestUser">Try: ?name=TestUser</a></p>
    </div>

    <div class="endpoint">
        <h3>3. Directory Traversal Test</h3>
        <p>Test path traversal vulnerabilities:</p>
        <code>?file=../../../etc/passwd</code><br>
        <code>?file=../../../../etc/shadow</code>
        <p><a href="?file=/etc/hostname">Try: ?file=/etc/hostname</a></p>
    </div>

    <h2>Server Information:</h2>
    <ul>
        <li><strong>PHP Version:</strong> <?php echo phpversion(); ?></li>
        <li><strong>Server Software:</strong> <?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?></li>
        <li><strong>Document Root:</strong> <?php echo $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown'; ?></li>
    </ul>

    <h2>Test Credentials:</h2>
    <ul>
        <li><strong>SSH:</strong> root:vulnerable123</li>
        <li><strong>SSH:</strong> testuser:password123</li>
        <li><strong>MySQL:</strong> root:(no password)</li>
        <li><strong>FTP:</strong> testuser:password123</li>
    </ul>

    <p><em>Use these endpoints to test your security scanning tools like Nmap, Nikto, SQLMap, etc.</em></p>
</body>
</html>
</content>
</invoke>