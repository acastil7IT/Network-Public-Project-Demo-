#!/usr/bin/env python3
"""
Advanced Security Scanner Integration
Integrates Nmap, Wireshark, and other professional security tools
"""

import subprocess
import json
import time
import os
import asyncio
import asyncpg
from datetime import datetime
import xml.etree.ElementTree as ET

class AdvancedSecurityScanner:
    def __init__(self):
        self.db_url = "postgresql://admin:secure123@postgres:5432/securenet"
        self.results_dir = "/app/results"
        self.db_pool = None
        
    async def init_db(self):
        """Initialize database connection"""
        try:
            self.db_pool = await asyncpg.create_pool(self.db_url, min_size=1, max_size=5)
            print("✅ Advanced scanner database connected")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
    
    async def create_advanced_incident(self, scan_type, severity, target, findings, tool_used):
        """Create incident with advanced scan results"""
        try:
            async with self.db_pool.acquire() as conn:
                description = f"Advanced {scan_type} scan completed using {tool_used}. Target: {target}. Findings: {len(findings)} items detected."
                
                incident_id = await conn.fetchval("""
                    INSERT INTO security_incidents 
                    (created_at, severity, incident_type, source_ip, description, status)
                    VALUES (NOW(), $1, $2, $3, $4, 'OPEN')
                    RETURNING id
                """, severity, f"ADVANCED_{scan_type}", target, description)
                
                # Store detailed findings in alerts
                for finding in findings[:5]:  # Limit to top 5 findings
                    await conn.execute("""
                        INSERT INTO alerts (incident_id, alert_type, message, created_at, acknowledged)
                        VALUES ($1, $2, $3, NOW(), false)
                    """, incident_id, scan_type, f"{tool_used}: {finding}")
                
                print(f"🚨 Advanced incident created: {scan_type} - {len(findings)} findings")
                return incident_id
                
        except Exception as e:
            print(f"❌ Failed to create advanced incident: {e}")
    
    def nmap_port_scan(self, target, scan_type="comprehensive"):
        """Advanced Nmap port scanning"""
        print(f"🔍 Starting Advanced Nmap Scan: {target}")
        print("=" * 60)
        
        # Different scan types
        scan_commands = {
            "stealth": ["nmap", "-sS", "-T4", "-p-", "--max-retries", "1"],
            "comprehensive": ["nmap", "-sS", "-sV", "-O", "-A", "--script=vuln"],
            "fast": ["nmap", "-T5", "-F"],
            "udp": ["nmap", "-sU", "--top-ports", "100"]
        }
        
        cmd = scan_commands.get(scan_type, scan_commands["comprehensive"])
        cmd.extend(["-oX", f"{self.results_dir}/nmap_{target.replace('.', '_')}.xml", target])
        
        try:
            print(f"🚀 Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print("✅ Nmap scan completed successfully")
                return self.parse_nmap_results(f"{self.results_dir}/nmap_{target.replace('.', '_')}.xml")
            else:
                print(f"❌ Nmap scan failed: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            print("⏰ Nmap scan timed out")
            return []
        except Exception as e:
            print(f"❌ Nmap scan error: {e}")
            return []
    
    def parse_nmap_results(self, xml_file):
        """Parse Nmap XML results"""
        findings = []
        try:
            if not os.path.exists(xml_file):
                return findings
                
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                # Get host info
                address = host.find('address').get('addr')
                state = host.find('status').get('state')
                
                if state == 'up':
                    findings.append(f"Host {address} is UP")
                    
                    # Get open ports
                    ports = host.find('ports')
                    if ports is not None:
                        for port in ports.findall('port'):
                            port_state = port.find('state')
                            if port_state.get('state') == 'open':
                                port_id = port.get('portid')
                                protocol = port.get('protocol')
                                
                                service = port.find('service')
                                if service is not None:
                                    service_name = service.get('name', 'unknown')
                                    version = service.get('version', '')
                                    findings.append(f"Open port {port_id}/{protocol} - {service_name} {version}")
                                else:
                                    findings.append(f"Open port {port_id}/{protocol}")
                    
                    # Get OS detection
                    os_elem = host.find('os')
                    if os_elem is not None:
                        os_matches = os_elem.findall('osmatch')
                        if os_matches:
                            os_name = os_matches[0].get('name')
                            findings.append(f"OS Detection: {os_name}")
            
            print(f"📊 Parsed {len(findings)} findings from Nmap results")
            return findings
            
        except Exception as e:
            print(f"❌ Error parsing Nmap results: {e}")
            return findings
    
    def wireshark_packet_capture(self, interface="eth0", duration=30, filter_expr=""):
        """Wireshark/tshark packet capture and analysis"""
        print(f"📡 Starting Wireshark Packet Capture")
        print(f"🔧 Interface: {interface}, Duration: {duration}s")
        print("=" * 60)
        
        pcap_file = f"{self.results_dir}/capture_{int(time.time())}.pcap"
        
        # Build tshark command
        cmd = [
            "tshark", 
            "-i", interface,
            "-a", f"duration:{duration}",
            "-w", pcap_file
        ]
        
        if filter_expr:
            cmd.extend(["-f", filter_expr])
        
        try:
            print(f"🚀 Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)
            
            if result.returncode == 0:
                print("✅ Packet capture completed")
                return self.analyze_pcap(pcap_file)
            else:
                print(f"❌ Packet capture failed: {result.stderr}")
                return []
                
        except Exception as e:
            print(f"❌ Packet capture error: {e}")
            return []
    
    def analyze_pcap(self, pcap_file):
        """Analyze captured packets for threats"""
        findings = []
        try:
            # Analyze with tshark
            analysis_commands = [
                # Protocol distribution
                ["tshark", "-r", pcap_file, "-q", "-z", "io,phs"],
                # Top talkers
                ["tshark", "-r", pcap_file, "-q", "-z", "conv,ip"],
                # Suspicious patterns
                ["tshark", "-r", pcap_file, "-Y", "tcp.flags.syn==1 and tcp.flags.ack==0", "-T", "fields", "-e", "ip.src", "-e", "tcp.dstport"]
            ]
            
            for cmd in analysis_commands:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0 and result.stdout.strip():
                    findings.append(f"Traffic Analysis: {result.stdout.strip()[:100]}")
            
            print(f"📊 Analyzed packet capture: {len(findings)} findings")
            return findings
            
        except Exception as e:
            print(f"❌ Error analyzing PCAP: {e}")
            return findings
    
    def vulnerability_scan(self, target):
        """Advanced vulnerability scanning with multiple tools"""
        print(f"🔍 Starting Vulnerability Scan: {target}")
        print("=" * 60)
        
        findings = []
        
        # Nikto web vulnerability scan
        try:
            print("🕷️  Running Nikto web scan...")
            nikto_cmd = ["nikto", "-h", f"http://{target}", "-Format", "txt"]
            result = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                nikto_findings = [line.strip() for line in result.stdout.split('\n') 
                                if line.strip() and not line.startswith('-') and not line.startswith('*')]
                findings.extend(nikto_findings[:5])  # Top 5 findings
                print(f"✅ Nikto found {len(nikto_findings)} potential issues")
            
        except Exception as e:
            print(f"❌ Nikto scan error: {e}")
        
        # Directory enumeration with dirb
        try:
            print("📁 Running directory enumeration...")
            dirb_cmd = ["dirb", f"http://{target}", "-S", "-w"]
            result = subprocess.run(dirb_cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                dirb_findings = [line.strip() for line in result.stdout.split('\n') 
                               if '==> DIRECTORY:' in line or 'CODE:200' in line]
                findings.extend(dirb_findings[:3])  # Top 3 findings
                print(f"✅ Directory scan found {len(dirb_findings)} items")
            
        except Exception as e:
            print(f"❌ Directory scan error: {e}")
        
        return findings
    
    def network_discovery(self, network_range="192.168.1.0/24"):
        """Network discovery and host enumeration"""
        print(f"🌐 Starting Network Discovery: {network_range}")
        print("=" * 60)
        
        findings = []
        
        try:
            # Host discovery
            print("🔍 Discovering live hosts...")
            discovery_cmd = ["nmap", "-sn", network_range]
            result = subprocess.run(discovery_cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Nmap scan report for' in line:
                        host = line.split('for ')[1].strip()
                        findings.append(f"Live host discovered: {host}")
                
                print(f"✅ Network discovery found {len(findings)} live hosts")
            
        except Exception as e:
            print(f"❌ Network discovery error: {e}")
        
        return findings

    async def run_comprehensive_scan(self, target="localhost"):
        """Run comprehensive security assessment"""
        print("🛡️  ADVANCED SECURITY ASSESSMENT")
        print("=" * 80)
        print(f"🎯 Target: {target}")
        print("🔧 Tools: Nmap, Wireshark, Nikto, Dirb")
        print("=" * 80)
        
        await self.init_db()
        
        all_findings = []
        
        # 1. Network Discovery
        print("\n1️⃣  NETWORK DISCOVERY")
        discovery_findings = self.network_discovery()
        if discovery_findings:
            await self.create_advanced_incident(
                "NETWORK_DISCOVERY", "LOW", target, discovery_findings, "Nmap"
            )
            all_findings.extend(discovery_findings)
        
        # 2. Port Scanning
        print("\n2️⃣  PORT SCANNING")
        port_findings = self.nmap_port_scan(target, "comprehensive")
        if port_findings:
            await self.create_advanced_incident(
                "PORT_SCAN", "MEDIUM", target, port_findings, "Nmap"
            )
            all_findings.extend(port_findings)
        
        # 3. Vulnerability Assessment
        print("\n3️⃣  VULNERABILITY ASSESSMENT")
        vuln_findings = self.vulnerability_scan(target)
        if vuln_findings:
            await self.create_advanced_incident(
                "VULNERABILITY_SCAN", "HIGH", target, vuln_findings, "Nikto/Dirb"
            )
            all_findings.extend(vuln_findings)
        
        # 4. Packet Capture (if interface available)
        print("\n4️⃣  PACKET ANALYSIS")
        try:
            packet_findings = self.wireshark_packet_capture("any", 15, "tcp")
            if packet_findings:
                await self.create_advanced_incident(
                    "PACKET_ANALYSIS", "MEDIUM", target, packet_findings, "Wireshark"
                )
                all_findings.extend(packet_findings)
        except Exception as e:
            print(f"⚠️  Packet capture skipped: {e}")
        
        # Summary
        print("\n" + "=" * 80)
        print("✅ COMPREHENSIVE SCAN COMPLETE")
        print("=" * 80)
        print(f"📊 Total Findings: {len(all_findings)}")
        print(f"🔍 Check your SecureNet Dashboard for detailed results")
        print("=" * 80)
        
        return all_findings

async def main():
    """Main scanner function"""
    scanner = AdvancedSecurityScanner()
    
    # Run comprehensive scan on localhost (safe target)
    await scanner.run_comprehensive_scan("localhost")

if __name__ == "__main__":
    asyncio.run(main())