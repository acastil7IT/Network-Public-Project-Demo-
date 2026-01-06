#!/usr/bin/env python3
"""
Network Traffic Injector
Injects network traffic data based on real attack patterns
"""

import asyncio
import asyncpg
import time
from datetime import datetime
import random

class TrafficInjector:
    def __init__(self):
        self.db_pool = None
        
    async def init_db(self):
        """Initialize database connection"""
        try:
            db_url = "postgresql://admin:secure123@localhost:5433/securenet"
            self.db_pool = await asyncpg.create_pool(db_url, min_size=2, max_size=10)
            print("✅ Traffic injector database connected")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            raise
    
    async def inject_port_scan_traffic(self, attacker_ip, target_ports):
        """Inject port scan traffic into database"""
        print(f"📡 Injecting port scan traffic from {attacker_ip}")
        
        async with self.db_pool.acquire() as conn:
            for i, port in enumerate(target_ports):
                await conn.execute("""
                    INSERT INTO network_traffic 
                    (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, flags, payload_hash)
                    VALUES (NOW() - INTERVAL '%s seconds', $1, '192.168.1.1', $2, $3, 'TCP', 64, 'SYN', $4)
                """, 30 - i*2, attacker_ip, 50000 + i, port, f"scan_{i:03d}")
                
                print(f"   📦 Packet: {attacker_ip}:{50000 + i} -> 192.168.1.1:{port}")
    
    async def inject_brute_force_traffic(self, attacker_ip, target_port, attempts):
        """Inject brute force traffic into database"""
        print(f"🔐 Injecting brute force traffic from {attacker_ip}")
        
        async with self.db_pool.acquire() as conn:
            for i in range(attempts):
                await conn.execute("""
                    INSERT INTO network_traffic 
                    (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, flags, payload_hash)
                    VALUES (NOW() - INTERVAL '%s seconds', $1, '192.168.1.1', $2, $3, 'TCP', 128, 'PSH', $4)
                """, 60 - i*3, attacker_ip, 40000 + i, target_port, f"auth_{i:03d}")
                
                if i % 3 == 0:
                    print(f"   🔑 Auth attempt {i+1}: {attacker_ip}:{40000 + i} -> 192.168.1.1:{target_port}")
    
    async def inject_dos_traffic(self, attacker_ip, target_port, request_count):
        """Inject DoS traffic into database"""
        print(f"💥 Injecting DoS traffic from {attacker_ip}")
        
        async with self.db_pool.acquire() as conn:
            for i in range(request_count):
                await conn.execute("""
                    INSERT INTO network_traffic 
                    (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, flags, payload_hash)
                    VALUES (NOW() - INTERVAL '%s seconds', $1, '192.168.1.1', $2, $3, 'TCP', 256, 'ACK', $4)
                """, 30 - (i % 30), attacker_ip, 60000 + (i % 1000), target_port, f"dos_{i:04d}")
                
                if i % 10 == 0:
                    print(f"   📡 DoS packet {i+1}/{request_count}")

async def main():
    """Main traffic injection"""
    print("🚀 SecureNet Traffic Injector")
    print("=" * 50)
    
    injector = TrafficInjector()
    await injector.init_db()
    
    print("\n📡 Injecting attack traffic patterns...")
    
    # Inject different attack patterns
    await injector.inject_port_scan_traffic(
        "203.0.113.200", 
        [22, 23, 80, 135, 443, 445, 1433, 3389]
    )
    
    await injector.inject_brute_force_traffic(
        "198.51.100.100", 
        22, 
        12
    )
    
    await injector.inject_dos_traffic(
        "192.0.2.50", 
        80, 
        25
    )
    
    print("\n✅ Traffic injection complete!")
    print("🔍 Check your dashboard for new network traffic data")

if __name__ == "__main__":
    asyncio.run(main())