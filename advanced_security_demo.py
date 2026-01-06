#!/usr/bin/env python3
"""
Advanced Security Demo Launcher
Demonstrates professional cybersecurity tools integration
"""

import subprocess
import time
import os
import sys

def run_command(cmd, description):
    """Run a command and display results"""
    print(f"\n🔧 {description}")
    print("=" * 60)
    print(f"Command: {' '.join(cmd)}")
    print("-" * 60)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print("✅ SUCCESS")
            if result.stdout.strip():
                print("Output:")
                print(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
        else:
            print("❌ FAILED")
            if result.stderr.strip():
                print("Error:")
                print(result.stderr[:200])
    except subprocess.TimeoutExpired:
        print("⏰ TIMEOUT - Command took too long")
    except Exception as e:
        print(f"❌ ERROR: {e}")

def demonstrate_nmap():
    """Demonstrate Nmap scanning capabilities"""
    print("\n🎯 NMAP DEMONSTRATION")
    print("=" * 80)
    
    # Basic port scan
    run_command(
        ["nmap", "-F", "localhost"],
        "Fast port scan of localhost"
    )
    
    # Service detection
    run_command(
        ["nmap", "-sV", "-p", "80,443,8001", "localhost"],
        "Service version detection"
    )
    
    # OS detection (requires root, will show what it would do)
    run_command(
        ["nmap", "-O", "--osscan-guess", "localhost"],
        "OS fingerprinting attempt"
    )

def demonstrate_network_tools():
    """Demonstrate network analysis tools"""
    print("\n🌐 NETWORK ANALYSIS DEMONSTRATION")
    print("=" * 80)
    
    # Network connectivity
    run_command(
        ["ping", "-c", "3", "localhost"],
        "Network connectivity test"
    )
    
    # Port connectivity
    run_command(
        ["nc", "-zv", "localhost", "8001"],
        "Port connectivity test (netcat)"
    )
    
    # Network statistics
    run_command(
        ["netstat", "-tuln"],
        "Active network connections"
    )

def demonstrate_web_scanning():
    """Demonstrate web vulnerability scanning"""
    print("\n🕷️  WEB SECURITY DEMONSTRATION")
    print("=" * 80)
    
    # HTTP headers analysis
    run_command(
        ["curl", "-I", "http://localhost:8001/health"],
        "HTTP headers analysis"
    )
    
    # Directory enumeration simulation
    endpoints = ["/admin", "/login", "/api", "/config", "/backup"]
    for endpoint in endpoints:
        run_command(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"http://localhost:8001{endpoint}"],
            f"Testing endpoint: {endpoint}"
        )

def create_security_report():
    """Create a security assessment report"""
    print("\n📊 GENERATING SECURITY REPORT")
    print("=" * 80)
    
    report = f"""
# Advanced Security Assessment Report
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
This report demonstrates advanced security scanning capabilities using professional tools:
- Nmap for network discovery and port scanning
- Network connectivity analysis
- Web application security testing
- Vulnerability assessment methodologies

## Tools Demonstrated
1. **Nmap** - Network discovery and security auditing
2. **Netcat** - Network connectivity testing
3. **Curl** - HTTP/HTTPS analysis
4. **Netstat** - Network connection monitoring

## Key Findings
- System responds to network scans
- Multiple services detected and analyzed
- Web application endpoints tested
- Security posture evaluated

## Recommendations
1. Implement network segmentation
2. Configure proper firewall rules
3. Regular security assessments
4. Monitor network traffic patterns

## Technical Details
This demonstration shows integration of professional cybersecurity tools
in an automated security assessment platform.
"""
    
    with open("security_assessment_report.txt", "w") as f:
        f.write(report)
    
    print("✅ Security report generated: security_assessment_report.txt")

def main():
    """Main demonstration function"""
    print("🛡️  ADVANCED SECURITY TOOLS DEMONSTRATION")
    print("=" * 80)
    print("This demo showcases professional cybersecurity tools integration")
    print("⚠️  Only scanning localhost and authorized targets")
    print("=" * 80)
    
    # Check if running in Docker
    if os.path.exists("/.dockerenv"):
        print("🐳 Running inside Docker container")
    else:
        print("💻 Running on host system")
    
    # Run demonstrations
    demonstrate_nmap()
    demonstrate_network_tools()
    demonstrate_web_scanning()
    create_security_report()
    
    print("\n" + "=" * 80)
    print("✅ ADVANCED SECURITY DEMONSTRATION COMPLETE")
    print("=" * 80)
    print("📊 Check your SecureNet Dashboard for integration results")
    print("📄 Security report saved to: security_assessment_report.txt")
    print("🔍 This demonstrates professional cybersecurity capabilities")
    print("=" * 80)

if __name__ == "__main__":
    main()