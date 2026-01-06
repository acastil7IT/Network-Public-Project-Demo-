#!/usr/bin/env python3
"""
Real-time Threat Detection Module
Monitors network activity and creates incidents automatically
"""

import asyncio
import asyncpg
import redis
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json

class RealTimeThreatDetector:
    def __init__(self):
        self.db_pool = None
        self.redis_client = None
        
        # Tracking structures for pattern detection
        self.port_access_tracker = defaultdict(set)  # IP -> set of ports
        self.failed_auth_tracker = defaultdict(deque)  # IP -> deque of timestamps
        self.request_rate_tracker = defaultdict(deque)  # IP -> deque of timestamps
        
        # Thresholds
        self.PORT_SCAN_THRESHOLD = 5  # ports accessed in timeframe
        self.BRUTE_FORCE_THRESHOLD = 8  # failed attempts in timeframe
        self.DOS_THRESHOLD = 50  # requests per minute
        self.TIME_WINDOW = 300  # 5 minutes in seconds
        
    async def init_connections(self):
        """Initialize database and Redis connections"""
        try:
            # Database connection
            db_url = "postgresql://admin:secure123@localhost:5433/securenet"
            self.db_pool = await asyncpg.create_pool(db_url, min_size=2, max_size=10)
            
            # Redis connection
            self.redis_client = redis.from_url("redis://localhost:6379", decode_responses=True)
            
            print("✅ Real-time detector connections established")
            
        except Exception as e:
            print(f"❌ Failed to initialize connections: {e}")
            raise
    
    async def create_incident(self, incident_type, severity, source_ip, description):
        """Create a new security incident"""
        try:
            async with self.db_pool.acquire() as conn:
                # Insert incident
                incident_id = await conn.fetchval("""
                    INSERT INTO security_incidents 
                    (created_at, severity, incident_type, source_ip, description, status)
                    VALUES (NOW(), $1, $2, $3, $4, 'OPEN')
                    RETURNING id
                """, severity, incident_type, source_ip, description)
                
                # Create corresponding alert
                await conn.execute("""
                    INSERT INTO alerts (incident_id, alert_type, message, created_at, acknowledged)
                    VALUES ($1, $2, $3, NOW(), false)
                """, incident_id, incident_type, f"REAL-TIME DETECTION: {description}")
                
                print(f"🚨 INCIDENT CREATED: {incident_type} from {source_ip}")
                return incident_id
                
        except Exception as e:
            print(f"❌ Failed to create incident: {e}")
            return None
    
    def detect_port_scan(self, source_ip, dest_port):
        """Detect port scanning behavior"""
        current_time = time.time()
        
        # Add port to tracking
        self.port_access_tracker[source_ip].add(dest_port)
        
        # Check if threshold exceeded
        if len(self.port_access_tracker[source_ip]) >= self.PORT_SCAN_THRESHOLD:
            ports_list = list(self.port_access_tracker[source_ip])
            description = f"Port scanning detected from {source_ip}. Accessed ports: {', '.join(map(str, ports_list))}"
            
            # Clear tracker to avoid duplicate incidents
            self.port_access_tracker[source_ip].clear()
            
            return {
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "description": description
            }
        
        return None
    
    def detect_brute_force(self, source_ip):
        """Detect brute force attacks"""
        current_time = time.time()
        
        # Add failed attempt
        self.failed_auth_tracker[source_ip].append(current_time)
        
        # Remove old entries (outside time window)
        while (self.failed_auth_tracker[source_ip] and 
               current_time - self.failed_auth_tracker[source_ip][0] > self.TIME_WINDOW):
            self.failed_auth_tracker[source_ip].popleft()
        
        # Check threshold
        if len(self.failed_auth_tracker[source_ip]) >= self.BRUTE_FORCE_THRESHOLD:
            attempts = len(self.failed_auth_tracker[source_ip])
            description = f"Brute force attack detected from {source_ip}. {attempts} failed authentication attempts in {self.TIME_WINDOW//60} minutes"
            
            # Clear tracker
            self.failed_auth_tracker[source_ip].clear()
            
            return {
                "type": "BRUTE_FORCE_ATTEMPT",
                "severity": "CRITICAL",
                "description": description
            }
        
        return None
    
    def detect_dos_attack(self, source_ip):
        """Detect Denial of Service attacks"""
        current_time = time.time()
        
        # Add request
        self.request_rate_tracker[source_ip].append(current_time)
        
        # Remove old entries (outside 1 minute window)
        while (self.request_rate_tracker[source_ip] and 
               current_time - self.request_rate_tracker[source_ip][0] > 60):
            self.request_rate_tracker[source_ip].popleft()
        
        # Check threshold (requests per minute)
        if len(self.request_rate_tracker[source_ip]) >= self.DOS_THRESHOLD:
            rps = len(self.request_rate_tracker[source_ip]) / 60
            description = f"DoS attack detected from {source_ip}. {rps:.1f} requests per second sustained"
            
            # Clear tracker
            self.request_rate_tracker[source_ip].clear()
            
            return {
                "type": "DOS_ATTACK",
                "severity": "CRITICAL",
                "description": description
            }
        
        return None
    
    async def analyze_network_activity(self):
        """Monitor network activity and detect threats"""
        print("🔍 Starting real-time threat analysis...")
        
        while True:
            try:
                # Get recent network traffic
                async with self.db_pool.acquire() as conn:
                    recent_traffic = await conn.fetch("""
                        SELECT source_ip, dest_port, timestamp, protocol
                        FROM network_traffic 
                        WHERE timestamp > NOW() - INTERVAL '1 minute'
                        ORDER BY timestamp DESC
                    """)
                
                # Analyze each traffic record
                for record in recent_traffic:
                    source_ip = str(record['source_ip'])
                    dest_port = record['dest_port']
                    
                    # Skip internal/local traffic for demo
                    if source_ip.startswith('127.') or source_ip.startswith('192.168.'):
                        continue
                    
                    # Detect port scanning
                    if dest_port:
                        port_scan = self.detect_port_scan(source_ip, dest_port)
                        if port_scan:
                            await self.create_incident(
                                port_scan["type"], 
                                port_scan["severity"], 
                                source_ip, 
                                port_scan["description"]
                            )
                    
                    # Detect brute force (simulate based on failed connections)
                    if dest_port in [22, 3389, 80, 443]:  # Common auth ports
                        brute_force = self.detect_brute_force(source_ip)
                        if brute_force:
                            await self.create_incident(
                                brute_force["type"],
                                brute_force["severity"],
                                source_ip,
                                brute_force["description"]
                            )
                    
                    # Detect DoS
                    dos_attack = self.detect_dos_attack(source_ip)
                    if dos_attack:
                        await self.create_incident(
                            dos_attack["type"],
                            dos_attack["severity"],
                            source_ip,
                            dos_attack["description"]
                        )
                
                # Wait before next analysis cycle
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                print(f"❌ Analysis error: {e}")
                await asyncio.sleep(5)

async def main():
    """Main detector function"""
    detector = RealTimeThreatDetector()
    await detector.init_connections()
    await detector.analyze_network_activity()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️  Real-time detector stopped by user")
    except Exception as e:
        print(f"❌ Detector crashed: {e}")
        exit(1)