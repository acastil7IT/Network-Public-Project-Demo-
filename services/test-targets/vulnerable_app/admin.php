<?php
// Vulnerable Admin Panel - FOR TESTING ONLY
session_start();

// Weak authentication
$admin_user = "admin";
$admin_pass = "admin123";

if (isset($_POST['username']) && isset($_POST['password'])) {
    if ($_POST['username'] == $admin_user && $_POST['password'] == $admin_pass) {
        $_SESSION['admin'] = true;
        echo "<div style='color: green;'>Login successful!</div>";
    } else {
        echo "<div style='color: red;'>Invalid credentials!</div>";
    }
}

// Command injection vulnerability (if logged in)
if (isset($_SESSION['admin']) && $_SESSION['admin'] && isset($_POST['command'])) {
    $command = $_POST['command'];
    echo "<h3>Command Output:</h3>";
    echo "<pre>";
    // Intentionally vulnerable - no sanitization
    system($command);
    echo "</pre>";
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Vulnerable Test App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .warning { background: #ffebee; border: 1px solid #f44336; padding: 15px; margin: 20px 0; }
        .login-form { background: #f5f5f5; padding: 20px; max-width: 400px; }
        .admin-panel { background: #e8f5e8; padding: 20px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🔐 Admin Panel (Vulnerable)</h1>
    
    <div class="warning">
        <strong>WARNING:</strong> This admin panel has intentional security vulnerabilities for testing.
    </div>

    <?php if (!isset($_SESSION['admin']) || !$_SESSION['admin']): ?>
    <div class="login-form">
        <h2>Admin Login</h2>
        <form method="POST">
            <p>
                <label>Username:</label><br>
                <input type="text" name="username" placeholder="admin">
            </p>
            <p>
                <label>Password:</label><br>
                <input type="password" name="password" placeholder="admin123">
            </p>
            <p>
                <input type="submit" value="Login">
            </p>
        </form>
        <p><em>Hint: Try default credentials admin/admin123</em></p>
    </div>
    <?php else: ?>
    <div class="admin-panel">
        <h2>Admin Commands (Command Injection Vulnerable)</h2>
        <form method="POST">
            <p>
                <label>Execute Command:</label><br>
                <input type="text" name="command" placeholder="ls -la" style="width: 300px;">
                <input type="submit" value="Execute">
            </p>
        </form>
        <p><em>Try commands like: ls, whoami, cat /etc/passwd, etc.</em></p>
        <p><a href="?logout=1">Logout</a></p>
    </div>
    <?php endif; ?>

    <?php
    // Simple logout
    if (isset($_GET['logout'])) {
        session_destroy();
        header("Location: admin.php");
        exit;
    }
    ?>
</body>
</html>
</content>
</invoke>