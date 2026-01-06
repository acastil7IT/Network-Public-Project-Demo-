#!/usr/bin/env python3
"""
SecureNet API Gateway
REST API for security dashboard and external integrations
"""

import json
import os
from datetime import datetime, timedelta
from typing import List, Optional

import asyncpg
import redis
import structlog
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# FastAPI app
app = FastAPI(
    title="SecureNet API",
    description="Network Security Monitoring API",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global connections
db_pool = None
redis_client = None

# Pydantic models
class SecurityIncident(BaseModel):
    id: int
    created_at: datetime
    severity: str
    incident_type: str
    source_ip: Optional[str]
    description: str
    status: str
    assigned_to: Optional[str]
    resolved_at: Optional[datetime]

class NetworkTraffic(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    packet_size: int

class Alert(BaseModel):
    id: int
    incident_id: int
    alert_type: str
    message: str
    created_at: datetime
    acknowledged: bool

class DashboardStats(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_incidents: int
    packets_last_hour: int
    top_source_ips: List[dict]
    incident_trends: List[dict]

# Startup/shutdown events
@app.on_event("startup")
async def startup():
    global db_pool, redis_client
    
    try:
        # Database connection
        db_url = os.getenv('DATABASE_URL')
        db_pool = await asyncpg.create_pool(db_url, min_size=2, max_size=20)
        
        # Redis connection
        redis_url = os.getenv('REDIS_URL')
        redis_client = redis.from_url(redis_url, decode_responses=True)
        
        logger.info("API Gateway started successfully")
        
    except Exception as e:
        logger.error("Failed to start API Gateway", error=str(e))
        raise

@app.on_event("shutdown")
async def shutdown():
    global db_pool
    if db_pool:
        await db_pool.close()

# Authentication (simplified for demo)
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # In production, validate JWT token here
    return {"username": "admin", "role": "security_analyst"}

# API Endpoints
@app.get("/")
async def root():
    return {"message": "SecureNet API Gateway", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    try:
        # Check database
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        
        # Check Redis
        redis_client.ping()
        
        return {"status": "healthy", "timestamp": datetime.now()}
        
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {str(e)}")

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(user=Depends(get_current_user)):
    """Get dashboard statistics"""
    try:
        async with db_pool.acquire() as conn:
            # Total incidents
            total_incidents = await conn.fetchval(
                "SELECT COUNT(*) FROM security_incidents"
            )
            
            # Open incidents
            open_incidents = await conn.fetchval(
                "SELECT COUNT(*) FROM security_incidents WHERE status = 'OPEN'"
            )
            
            # Critical incidents
            critical_incidents = await conn.fetchval(
                "SELECT COUNT(*) FROM security_incidents WHERE severity = 'CRITICAL'"
            )
            
            # Packets last hour
            packets_last_hour = await conn.fetchval("""
                SELECT COUNT(*) FROM network_traffic 
                WHERE timestamp > NOW() - INTERVAL '1 hour'
            """)
            
            # Top source IPs
            top_ips = await conn.fetch("""
                SELECT source_ip::text as source_ip, COUNT(*) as count
                FROM network_traffic 
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                GROUP BY source_ip 
                ORDER BY count DESC 
                LIMIT 5
            """)
            
            # Incident trends (last 7 days)
            trends = await conn.fetch("""
                SELECT DATE(created_at) as date, COUNT(*) as count
                FROM security_incidents 
                WHERE created_at > NOW() - INTERVAL '7 days'
                GROUP BY DATE(created_at)
                ORDER BY date
            """)
        
        return DashboardStats(
            total_incidents=total_incidents or 0,
            open_incidents=open_incidents or 0,
            critical_incidents=critical_incidents or 0,
            packets_last_hour=packets_last_hour or 0,
            top_source_ips=[{"ip": str(row["source_ip"]), "count": row["count"]} for row in top_ips],
            incident_trends=[{"date": str(row["date"]), "count": row["count"]} for row in trends]
        )
        
    except Exception as e:
        logger.error("Failed to get dashboard stats", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve dashboard stats")

@app.get("/api/incidents", response_model=List[SecurityIncident])
async def get_incidents(
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Get security incidents with optional filtering"""
    try:
        query = "SELECT * FROM security_incidents WHERE 1=1"
        params = []
        
        if severity:
            query += f" AND severity = ${len(params) + 1}"
            params.append(severity)
            
        if status:
            query += f" AND status = ${len(params) + 1}"
            params.append(status)
            
        query += f" ORDER BY created_at DESC LIMIT ${len(params) + 1}"
        params.append(limit)
        
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            
        return [SecurityIncident(**{**dict(row), 'source_ip': str(row['source_ip']) if row['source_ip'] else None}) for row in rows]
        
    except Exception as e:
        logger.error("Failed to get incidents", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve incidents")

@app.get("/api/traffic", response_model=List[NetworkTraffic])
async def get_network_traffic(
    limit: int = 100,
    source_ip: Optional[str] = None,
    user=Depends(get_current_user)
):
    """Get network traffic data"""
    try:
        query = "SELECT * FROM network_traffic WHERE 1=1"
        params = []
        
        if source_ip:
            query += f" AND source_ip = ${len(params) + 1}"
            params.append(source_ip)
            
        query += f" ORDER BY timestamp DESC LIMIT ${len(params) + 1}"
        params.append(limit)
        
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            
        return [NetworkTraffic(**{**dict(row), 'source_ip': str(row['source_ip']), 'dest_ip': str(row['dest_ip'])}) for row in rows]
        
    except Exception as e:
        logger.error("Failed to get traffic data", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve traffic data")

@app.get("/api/alerts/live")
async def get_live_alerts(user=Depends(get_current_user)):
    """Get live alerts from Redis stream"""
    try:
        # Get recent alerts from Redis
        alerts = redis_client.lrange('alert_stream', 0, 9)  # Last 10 alerts
        
        parsed_alerts = []
        for alert_json in alerts:
            try:
                alert_data = json.loads(alert_json)
                parsed_alerts.append(alert_data)
            except json.JSONDecodeError:
                continue
                
        return {"alerts": parsed_alerts}
        
    except Exception as e:
        logger.error("Failed to get live alerts", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve live alerts")

@app.post("/api/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(
    incident_id: int,
    user=Depends(get_current_user)
):
    """Acknowledge a security incident"""
    try:
        async with db_pool.acquire() as conn:
            # Update incident status
            result = await conn.execute("""
                UPDATE security_incidents 
                SET status = 'ACKNOWLEDGED', assigned_to = $1
                WHERE id = $2
            """, user["username"], incident_id)
            
            if result == "UPDATE 0":
                raise HTTPException(status_code=404, detail="Incident not found")
                
            # Update related alerts
            await conn.execute("""
                UPDATE alerts 
                SET acknowledged = TRUE, acknowledged_by = $1, acknowledged_at = NOW()
                WHERE incident_id = $2
            """, user["username"], incident_id)
        
        logger.info("Incident acknowledged", incident_id=incident_id, user=user["username"])
        return {"message": "Incident acknowledged successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to acknowledge incident", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to acknowledge incident")

@app.post("/api/incidents/{incident_id}/resolve")
async def resolve_incident(
    incident_id: int,
    user=Depends(get_current_user)
):
    """Resolve a security incident"""
    try:
        async with db_pool.acquire() as conn:
            result = await conn.execute("""
                UPDATE security_incidents 
                SET status = 'RESOLVED', resolved_at = NOW()
                WHERE id = $1
            """, incident_id)
            
            if result == "UPDATE 0":
                raise HTTPException(status_code=404, detail="Incident not found")
        
        logger.info("Incident resolved", incident_id=incident_id, user=user["username"])
        return {"message": "Incident resolved successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to resolve incident", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to resolve incident")

@app.post("/api/advanced-scan")
async def start_advanced_scan(
    scan_request: dict,
    user=Depends(get_current_user)
):
    """Start an advanced security scan"""
    try:
        target = scan_request.get("target", "localhost")
        scan_type = scan_request.get("scan_type", "comprehensive")
        
        logger.info("Advanced scan requested", target=target, scan_type=scan_type)
        
        # For demo purposes, simulate scan results
        # In production, this would trigger actual security tools
        
        scan_results = []
        
        if scan_type == "comprehensive":
            scan_results = [
                {
                    "finding": "Open Port: 80/tcp (HTTP)",
                    "severity": "INFO",
                    "tool": "Nmap",
                    "description": "HTTP service detected on port 80"
                },
                {
                    "finding": "Open Port: 443/tcp (HTTPS)", 
                    "severity": "INFO",
                    "tool": "Nmap",
                    "description": "HTTPS service detected on port 443"
                },
                {
                    "finding": "SSH Service: OpenSSH 8.2",
                    "severity": "LOW",
                    "tool": "Nmap",
                    "description": "SSH service version detected"
                },
                {
                    "finding": "Web Server: Apache/2.4.41",
                    "severity": "INFO", 
                    "tool": "Nmap",
                    "description": "Apache web server detected"
                }
            ]
        elif scan_type == "vulnerability":
            scan_results = [
                {
                    "finding": "Directory Listing Enabled",
                    "severity": "MEDIUM",
                    "tool": "Nikto",
                    "description": "Server allows directory browsing"
                },
                {
                    "finding": "Missing Security Headers",
                    "severity": "LOW",
                    "tool": "Nikto", 
                    "description": "X-Frame-Options header not set"
                },
                {
                    "finding": "Admin Panel Found: /admin",
                    "severity": "HIGH",
                    "tool": "Dirb",
                    "description": "Administrative interface discovered"
                }
            ]
        elif scan_type == "fast":
            scan_results = [
                {
                    "finding": "Open Port: 80/tcp",
                    "severity": "INFO",
                    "tool": "Nmap",
                    "description": "HTTP port open"
                },
                {
                    "finding": "Open Port: 443/tcp",
                    "severity": "INFO", 
                    "tool": "Nmap",
                    "description": "HTTPS port open"
                }
            ]
        
        # Create an incident for high-severity findings
        high_severity_findings = [f for f in scan_results if f["severity"] in ["HIGH", "CRITICAL"]]
        if high_severity_findings:
            async with db_pool.acquire() as conn:
                description = f"Advanced {scan_type} scan found {len(high_severity_findings)} high-severity issues on {target}"
                await conn.execute("""
                    INSERT INTO security_incidents 
                    (created_at, severity, incident_type, source_ip, description, status)
                    VALUES (NOW(), 'MEDIUM', 'ADVANCED_SCAN', $1, $2, 'OPEN')
                """, target, description)
        
        return {
            "status": "completed",
            "target": target,
            "scan_type": scan_type,
            "findings": scan_results,
            "total_findings": len(scan_results),
            "high_severity": len(high_severity_findings)
        }
        
    except Exception as e:
        logger.error("Advanced scan failed", error=str(e))
        raise HTTPException(status_code=500, detail="Advanced scan failed")

@app.get("/api/scan-history")
async def get_scan_history(user=Depends(get_current_user)):
    """Get scan history"""
    try:
        # Return mock scan history for demo
        history = [
            {
                "id": 1,
                "target": "localhost",
                "type": "comprehensive",
                "timestamp": "2026-01-06T18:30:00Z",
                "findings": 4,
                "status": "completed"
            },
            {
                "id": 2,
                "target": "192.168.1.1",
                "type": "vulnerability", 
                "timestamp": "2026-01-06T17:15:00Z",
                "findings": 3,
                "status": "completed"
            }
        ]
        
        return {"scans": history}
        
    except Exception as e:
        logger.error("Failed to get scan history", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve scan history")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)