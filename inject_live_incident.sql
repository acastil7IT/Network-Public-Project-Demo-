-- Live Security Incident Injection
-- This simulates real-time threat detection

-- Insert a new port scan incident (happening NOW)
INSERT INTO security_incidents (created_at, severity, incident_type, source_ip, description, status, assigned_to) VALUES
(NOW(), 'HIGH', 'PORT_SCAN', '203.0.113.100', 'LIVE ATTACK: Port scanning detected from external IP. Scanned ports: 22, 23, 80, 135, 443, 445, 1433, 3389', 'OPEN', NULL);

-- Get the incident ID for alerts
DO $$
DECLARE
    new_incident_id INTEGER;
BEGIN
    -- Get the ID of the incident we just created
    SELECT id INTO new_incident_id FROM security_incidents WHERE source_ip = '203.0.113.100' ORDER BY created_at DESC LIMIT 1;
    
    -- Insert corresponding alert
    INSERT INTO alerts (incident_id, alert_type, message, created_at, acknowledged) VALUES
    (new_incident_id, 'PORT_SCAN', 'LIVE THREAT: Multiple port scan attempts detected from 203.0.113.100', NOW(), false);
END $$;

-- Insert network traffic showing the scan
INSERT INTO network_traffic (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, flags, payload_hash) VALUES
(NOW(), '203.0.113.100', '192.168.1.1', 54321, 22, 'TCP', 64, 'SYN', 'live001'),
(NOW(), '203.0.113.100', '192.168.1.1', 54322, 23, 'TCP', 64, 'SYN', 'live002'),
(NOW(), '203.0.113.100', '192.168.1.1', 54323, 80, 'TCP', 64, 'SYN', 'live003'),
(NOW(), '203.0.113.100', '192.168.1.1', 54324, 135, 'TCP', 64, 'SYN', 'live004'),
(NOW(), '203.0.113.100', '192.168.1.1', 54325, 443, 'TCP', 64, 'SYN', 'live005'),
(NOW(), '203.0.113.100', '192.168.1.1', 54326, 445, 'TCP', 64, 'SYN', 'live006'),
(NOW(), '203.0.113.100', '192.168.1.1', 54327, 1433, 'TCP', 64, 'SYN', 'live007'),
(NOW(), '203.0.113.100', '192.168.1.1', 54328, 3389, 'TCP', 64, 'SYN', 'live008');

-- Show confirmation
SELECT 'LIVE INCIDENT CREATED!' as status, 
       COUNT(*) as new_incidents 
FROM security_incidents 
WHERE source_ip = '203.0.113.100';