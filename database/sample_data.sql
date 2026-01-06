-- Sample data for SecureNet Monitor

-- Insert sample network traffic
INSERT INTO network_traffic (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_size, flags, payload_hash) VALUES
(NOW() - INTERVAL '1 hour', '192.168.1.100', '8.8.8.8', 53421, 80, 'TCP', 1024, 'SYN', 'a1b2c3d4'),
(NOW() - INTERVAL '1 hour', '192.168.1.101', '10.0.0.1', 45123, 443, 'TCP', 512, 'ACK', 'e5f6g7h8'),
(NOW() - INTERVAL '50 minutes', '192.168.1.102', '172.16.0.1', 33445, 22, 'TCP', 256, 'SYN', 'i9j0k1l2'),
(NOW() - INTERVAL '45 minutes', '10.0.0.50', '192.168.1.100', 80, 54321, 'TCP', 2048, 'PSH', 'm3n4o5p6'),
(NOW() - INTERVAL '40 minutes', '192.168.1.103', '8.8.4.4', 12345, 53, 'UDP', 128, NULL, 'q7r8s9t0'),
(NOW() - INTERVAL '35 minutes', '172.16.0.10', '192.168.1.101', 443, 65432, 'TCP', 1536, 'FIN', 'u1v2w3x4'),
(NOW() - INTERVAL '30 minutes', '192.168.1.104', '203.0.113.1', 23456, 8080, 'TCP', 768, 'RST', 'y5z6a7b8'),
(NOW() - INTERVAL '25 minutes', '10.0.0.25', '192.168.1.102', 3389, 54123, 'TCP', 1280, 'SYN', 'c9d0e1f2'),
(NOW() - INTERVAL '20 minutes', '192.168.1.105', '1.1.1.1', 34567, 80, 'TCP', 896, 'ACK', 'g3h4i5j6'),
(NOW() - INTERVAL '15 minutes', '172.16.0.20', '192.168.1.103', 22, 45678, 'TCP', 640, 'PSH', 'k7l8m9n0'),
(NOW() - INTERVAL '10 minutes', '192.168.1.106', '8.8.8.8', 45678, 53, 'UDP', 192, NULL, 'o1p2q3r4'),
(NOW() - INTERVAL '5 minutes', '10.0.0.75', '192.168.1.104', 135, 56789, 'TCP', 384, 'SYN', 's5t6u7v8'),
(NOW() - INTERVAL '2 minutes', '192.168.1.107', '203.0.113.5', 56789, 443, 'TCP', 1152, 'ACK', 'w9x0y1z2'),
(NOW() - INTERVAL '1 minute', '172.16.0.30', '192.168.1.105', 445, 67890, 'TCP', 2560, 'PSH', 'a3b4c5d6');

-- Insert sample security incidents
INSERT INTO security_incidents (created_at, severity, incident_type, source_ip, description, status, assigned_to) VALUES
(NOW() - INTERVAL '2 hours', 'HIGH', 'PORT_SCAN', '10.0.0.50', 'Multiple port scan attempts detected from external IP', 'OPEN', NULL),
(NOW() - INTERVAL '1.5 hours', 'MEDIUM', 'SUSPICIOUS_PORT_ACCESS', '172.16.0.10', 'Access to administrative port 22 from unusual source', 'ACKNOWLEDGED', 'security_team'),
(NOW() - INTERVAL '1 hour', 'CRITICAL', 'NETWORK_ANOMALY', '192.168.1.107', 'Anomalous network behavior detected with high confidence', 'OPEN', NULL),
(NOW() - INTERVAL '45 minutes', 'LOW', 'UNUSUAL_TRAFFIC', '10.0.0.25', 'Unusual traffic pattern detected during off-hours', 'RESOLVED', 'admin'),
(NOW() - INTERVAL '30 minutes', 'HIGH', 'BRUTE_FORCE_ATTEMPT', '172.16.0.20', 'Multiple failed authentication attempts detected', 'ACKNOWLEDGED', 'security_analyst'),
(NOW() - INTERVAL '15 minutes', 'MEDIUM', 'SUSPICIOUS_PORT_ACCESS', '10.0.0.75', 'Access to Windows RPC port 135 detected', 'OPEN', NULL);

-- Insert corresponding alerts
INSERT INTO alerts (incident_id, alert_type, message, created_at, acknowledged) VALUES
(1, 'PORT_SCAN', 'Port scanning activity detected from 10.0.0.50', NOW() - INTERVAL '2 hours', false),
(2, 'SUSPICIOUS_PORT_ACCESS', 'SSH access attempt from 172.16.0.10', NOW() - INTERVAL '1.5 hours', true),
(3, 'NETWORK_ANOMALY', 'High confidence anomaly detected from 192.168.1.107', NOW() - INTERVAL '1 hour', false),
(4, 'UNUSUAL_TRAFFIC', 'Off-hours traffic from 10.0.0.25', NOW() - INTERVAL '45 minutes', true),
(5, 'BRUTE_FORCE_ATTEMPT', 'Multiple auth failures from 172.16.0.20', NOW() - INTERVAL '30 minutes', true),
(6, 'SUSPICIOUS_PORT_ACCESS', 'RPC port access from 10.0.0.75', NOW() - INTERVAL '15 minutes', false);

-- Insert sample network devices
INSERT INTO network_devices (ip_address, mac_address, hostname, device_type, os_fingerprint, last_seen, risk_score) VALUES
('192.168.1.100', '00:1B:44:11:3A:B7', 'workstation-01', 'Desktop', 'Windows 10', NOW() - INTERVAL '5 minutes', 2),
('192.168.1.101', '00:1B:44:11:3A:B8', 'laptop-02', 'Laptop', 'macOS 12', NOW() - INTERVAL '3 minutes', 1),
('192.168.1.102', '00:1B:44:11:3A:B9', 'server-01', 'Server', 'Ubuntu 20.04', NOW() - INTERVAL '1 minute', 0),
('10.0.0.50', '00:1B:44:11:3A:C1', 'unknown-device', 'Unknown', 'Unknown', NOW() - INTERVAL '2 hours', 8),
('172.16.0.10', '00:1B:44:11:3A:C2', 'external-host', 'Unknown', 'Linux', NOW() - INTERVAL '1.5 hours', 6),
('192.168.1.103', '00:1B:44:11:3A:BA', 'workstation-03', 'Desktop', 'Windows 11', NOW() - INTERVAL '10 minutes', 1),
('10.0.0.25', '00:1B:44:11:3A:C3', 'suspicious-host', 'Unknown', 'Unknown', NOW() - INTERVAL '45 minutes', 5);