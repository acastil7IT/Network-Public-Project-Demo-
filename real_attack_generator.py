#!/usr/bin/env python3
"""
SecureNet Real Attack Generator
Generates actual network traffic that triggers threat detection
"""

import socket
import threading
import time
import random
import subprocess
import requests
from datetime import datetime

class RealAttackGenerator:
    def __init__(self):
        self.target_host = "localhost"
        self.attack_results = []
        
    def port_scan_attack(self, target_ports=None):
        """Generate real port scanning traffic"""
        if target_ports is None:
            target_ports = [22, 23, 80, 135, 443, 445, 1433, 3389, 5432, 8001]
            
        print(f"🔍 Starting REAL Port Scan Attack on {self.target_host}")
        print(f"🎯 Target Ports: {target_ports}")
        print("=" * 60)
        
        open_ports = []
        closed_ports = []
        
        for port in target_ports:
            try:
                print(f"📡 Scanning port {port}... ", end="", flush=True)
                
                # Create actual network connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 1 second timeout
                
                result = sock.connect_ex((self.target_host, port))
                
                if result == 0:
                    print("🟢 OPEN")
                    open_ports.append(port)
                else:
                    print("🔴 CLOSED")
                    closed_ports.append(port)
                    
                sock.close()
                time.sleep(0.2)  # Small delay between scans
                
            except Exception as e:
                print(f"❌ ERROR: {e}")
                closed_ports.append(port)
        
        print("\n📊 Scan Results:")
        print(f"   🟢 Open Ports: {open_ports}")
        print(f"   🔴 Closed Ports: {closed_ports}")
        
        return {
            "attack_type": "PORT_SCAN",
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "total_scanned": len(target_ports)
        }
    
    def brute_force_attack(self, target_port=8001, attempts=10):
        """Generate real brute force attack traffic"""
        print(f"\n🔐 Starting REAL Brute Force Attack")
        print(f"🎯 Target: {self.target_host}:{target_port}")
        print(f"🔢 Attempts: {attempts}")
        print("=" * 60)
        
        usernames = ["admin", "root", "user", "administrator", "test", "guest", "demo"]
        passwords = ["password", "123456", "admin", "root", "password123", "qwerty"]
        
        failed_attempts = 0
        
        for i in range(attempts):
            username = random.choice(usernames)
            password = random.choice(passwords)
            
            try:
                print(f"🔑 Attempt {i+1}: {username}:{password} ... ", end="", flush=True)
                
                # Try to make HTTP request with basic auth (simulating login)
                response = requests.get(
                    f"http://{self.target_host}:{target_port}/api/dashboard/stats",
                    auth=(username, password),
                    timeout=2
                )
                
                if response.status_code == 401:
                    print("❌ FAILED")
                    failed_attempts += 1
                else:
                    print("✅ SUCCESS (unexpected!)")
                    
            except requests.exceptions.RequestException:
                print("❌ FAILED (connection error)")
                failed_attempts += 1
            
            time.sleep(0.5)  # Delay between attempts
        
        print(f"\n📊 Brute Force Results:")
        print(f"   ❌ Failed Attempts: {failed_attempts}")
        print(f"   📈 Success Rate: {((attempts - failed_attempts) / attempts) * 100:.1f}%")
        
        return {
            "attack_type": "BRUTE_FORCE",
            "failed_attempts": failed_attempts,
            "target_port": target_port
        }
    
    def dos_attack(self, target_port=8001, duration=10):
        """Generate Denial of Service attack traffic"""
        print(f"\n💥 Starting REAL DoS Attack")
        print(f"🎯 Target: {self.target_host}:{target_port}")
        print(f"⏱️  Duration: {duration} seconds")
        print("=" * 60)
        
        start_time = time.time()
        request_count = 0
        
        def send_requests():
            nonlocal request_count
            while time.time() - start_time < duration:
                try:
                    response = requests.get(
                        f"http://{self.target_host}:{target_port}/health",
                        timeout=1
                    )
                    request_count += 1
                    if request_count % 10 == 0:
                        print(f"📡 Sent {request_count} requests...")
                except:
                    pass
                time.sleep(0.1)
        
        # Launch multiple threads for concurrent requests
        threads = []
        for i in range(5):  # 5 concurrent threads
            thread = threading.Thread(target=send_requests)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        print(f"\n📊 DoS Attack Results:")
        print(f"   📡 Total Requests: {request_count}")
        print(f"   📈 Requests/Second: {request_count / duration:.1f}")
        
        return {
            "attack_type": "DOS_ATTACK",
            "total_requests": request_count,
            "duration": duration,
            "rps": request_count / duration
        }
    
    def vulnerability_scan(self):
        """Scan for common vulnerabilities"""
        print(f"\n🔍 Starting REAL Vulnerability Scan")
        print("=" * 60)
        
        # Common vulnerability endpoints to test
        vuln_paths = [
            "/admin",
            "/login",
            "/api/users",
            "/config",
            "/backup",
            "/.env",
            "/database",
            "/phpmyadmin",
            "/wp-admin",
            "/api/v1/users"
        ]
        
        found_endpoints = []
        
        for path in vuln_paths:
            try:
                print(f"🔍 Testing {path}... ", end="", flush=True)
                
                response = requests.get(
                    f"http://{self.target_host}:8001{path}",
                    timeout=2
                )
                
                if response.status_code != 404:
                    print(f"🟡 FOUND ({response.status_code})")
                    found_endpoints.append((path, response.status_code))
                else:
                    print("🔴 NOT FOUND")
                    
            except requests.exceptions.RequestException:
                print("❌ ERROR")
            
            time.sleep(0.3)
        
        print(f"\n📊 Vulnerability Scan Results:")
        if found_endpoints:
            print("   🟡 Found Endpoints:")
            for path, status in found_endpoints:
                print(f"      {path} (HTTP {status})")
        else:
            print("   🟢 No obvious vulnerabilities found")
        
        return {
            "attack_type": "VULN_SCAN",
            "found_endpoints": found_endpoints
        }

def main():
    """Main attack simulation"""
    print("🚨 SecureNet REAL Attack Generator")
    print("=" * 80)
    print("⚠️  WARNING: This generates actual network traffic!")
    print("   Only use in controlled environments for testing.")
    print("=" * 80)
    print()
    
    generator = RealAttackGenerator()
    
    print("🎬 Starting Real Attack Sequence...")
    print("📊 Monitor your dashboard at: http://localhost:3000")
    print()
    
    # Execute attacks in sequence
    results = []
    
    try:
        # 1. Port Scan
        result1 = generator.port_scan_attack()
        results.append(result1)
        time.sleep(2)
        
        # 2. Brute Force
        result2 = generator.brute_force_attack(attempts=15)
        results.append(result2)
        time.sleep(2)
        
        # 3. Vulnerability Scan
        result3 = generator.vulnerability_scan()
        results.append(result3)
        time.sleep(2)
        
        # 4. DoS Attack (short duration)
        result4 = generator.dos_attack(duration=5)
        results.append(result4)
        
    except KeyboardInterrupt:
        print("\n⚠️  Attack sequence interrupted by user")
    
    print("\n" + "=" * 80)
    print("✅ REAL ATTACK SEQUENCE COMPLETE!")
    print("=" * 80)
    print()
    print("📊 Attack Summary:")
    for i, result in enumerate(results, 1):
        print(f"   {i}. {result['attack_type']}: Executed")
    
    print()
    print("🔍 Next Steps:")
    print("   1. Check your SecureNet Dashboard for new incidents")
    print("   2. Look for traffic from your local IP in Network Traffic")
    print("   3. Monitor Live Alerts for real-time detections")
    print("   4. Practice incident response on the detected threats")
    print()
    print("🛡️  Your platform should now show REAL attack data!")

if __name__ == "__main__":
    main()