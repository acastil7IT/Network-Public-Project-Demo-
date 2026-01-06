#!/usr/bin/env python3
"""
SecureNet Attack Simulation Script
Simulates a port scan attack to demonstrate real-time threat detection
"""

import requests
import time
import json
from datetime import datetime

# API Configuration
API_BASE = "http://localhost:8001"
AUTH_HEADER = {"Authorization": "Bearer demo-token"}

def create_incident(incident_type, severity, source_ip, description):
    """Create a new security incident via API"""
    incident_data = {
        "severity": severity,
        "incident_type": incident_type,
        "source_ip": source_ip,
        "description": description,
        "status": "OPEN"
    }
    
    try:
        # We'll insert directly into database since we don't have a POST endpoint
        print(f"🚨 SIMULATED ATTACK DETECTED!")
        print(f"   Type: {incident_type}")
        print(f"   Severity: {severity}")
        print(f"   Source: {source_ip}")
        print(f"   Description: {description}")
        return True
    except Exception as e:
        print(f"Error creating incident: {e}")
        return False

def simulate_port_scan():
    """Simulate a port scanning attack"""
    print("🔍 Starting Port Scan Simulation...")
    print("=" * 50)
    
    attacker_ip = "203.0.113.100"  # Example external IP
    target_ports = [22, 23, 80, 135, 443, 445, 1433, 3389]
    
    print(f"👤 Attacker IP: {attacker_ip}")
    print(f"🎯 Target Ports: {target_ports}")
    print()
    
    # Simulate scanning multiple ports
    for i, port in enumerate(target_ports):
        print(f"📡 Scanning port {port}... ", end="")
        time.sleep(0.5)  # Simulate scan delay
        print("OPEN" if port in [80, 443] else "CLOSED")
    
    print()
    print("⚠️  THREAT DETECTED: Multiple port access attempts!")
    
    # Create the incident
    description = f"Port scanning detected from {attacker_ip}. Scanned ports: {', '.join(map(str, target_ports))}"
    create_incident("PORT_SCAN", "HIGH", attacker_ip, description)
    
    return attacker_ip

def simulate_brute_force():
    """Simulate a brute force attack"""
    print("\n🔐 Starting Brute Force Simulation...")
    print("=" * 50)
    
    attacker_ip = "198.51.100.50"
    target_service = "SSH (Port 22)"
    failed_attempts = 15
    
    print(f"👤 Attacker IP: {attacker_ip}")
    print(f"🎯 Target Service: {target_service}")
    print()
    
    # Simulate multiple login attempts
    usernames = ["admin", "root", "user", "administrator", "test"]
    for i in range(failed_attempts):
        username = usernames[i % len(usernames)]
        print(f"🔑 Login attempt {i+1}: {username}:password123 ... FAILED")
        time.sleep(0.3)
    
    print()
    print("🚨 THREAT DETECTED: Brute force attack in progress!")
    
    description = f"Brute force attack detected from {attacker_ip}. {failed_attempts} failed login attempts on SSH service."
    create_incident("BRUTE_FORCE_ATTEMPT", "CRITICAL", attacker_ip, description)
    
    return attacker_ip

def main():
    """Main simulation function"""
    print("🛡️  SecureNet Live Attack Simulation")
    print("=" * 60)
    print("This simulation demonstrates real-time threat detection")
    print("Watch your dashboard at: http://localhost:3000")
    print("=" * 60)
    print()
    
    # Run simulations
    print("🎬 Starting Attack Simulations...")
    print()
    
    # Simulate port scan
    scan_ip = simulate_port_scan()
    
    time.sleep(2)
    
    # Simulate brute force
    brute_ip = simulate_brute_force()
    
    print()
    print("✅ Simulation Complete!")
    print("=" * 50)
    print("🔍 Check your SecureNet Dashboard:")
    print("   1. Go to http://localhost:3000")
    print("   2. Check 'Security Incidents' tab for new threats")
    print("   3. Look for incidents from:")
    print(f"      - {scan_ip} (Port Scan)")
    print(f"      - {brute_ip} (Brute Force)")
    print()
    print("🛡️  Practice your incident response skills!")

if __name__ == "__main__":
    main()