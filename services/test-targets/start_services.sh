#!/bin/bash

echo "🎯 Starting Vulnerable Test Environment"
echo "⚠️  FOR TESTING PURPOSES ONLY"

# Start SSH
service ssh start
echo "✅ SSH started on port 22"

# Start Apache
service apache2 start
echo "✅ Apache started on port 80"

# Start MySQL
service mysql start
echo "✅ MySQL started on port 3306"

# Start FTP
service vsftpd start
echo "✅ FTP started on port 21"

# Create a simple vulnerable web service
python3 -c "
import http.server
import socketserver
import threading

class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/admin':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>Admin Panel - Vulnerable!</h1>')
        elif self.path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<form><input name=\"user\"><input name=\"pass\" type=\"password\"></form>')
        else:
            super().do_GET()

with socketserver.TCPServer(('', 8080), VulnerableHandler) as httpd:
    print('✅ Vulnerable web service started on port 8080')
    httpd.serve_forever()
" &

echo "🎯 Test environment ready!"
echo "📊 Available services:"
echo "   - SSH (port 22) - root:vulnerable123"
echo "   - HTTP (port 80) - Apache web server"
echo "   - HTTP (port 8080) - Vulnerable web app"
echo "   - FTP (port 21) - Anonymous access"
echo "   - MySQL (port 3306) - Database server"

# Keep container running
tail -f /dev/null