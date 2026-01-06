// Mock API service for demo deployment
// This replaces real API calls with realistic mock data for public safety

const mockIncidents = [
  {
    id: 1,
    created_at: new Date(Date.now() - 3600000).toISOString(),
    severity: 'HIGH',
    incident_type: 'PORT_SCAN',
    source_ip: '192.168.1.100',
    description: 'Suspicious port scanning activity detected from internal network',
    status: 'OPEN',
    assigned_to: null,
    resolved_at: null
  },
  {
    id: 2,
    created_at: new Date(Date.now() - 7200000).toISOString(),
    severity: 'CRITICAL',
    incident_type: 'BRUTE_FORCE',
    source_ip: '10.0.0.50',
    description: 'Multiple failed SSH login attempts detected',
    status: 'ACKNOWLEDGED',
    assigned_to: 'security_team',
    resolved_at: null
  },
  {
    id: 3,
    created_at: new Date(Date.now() - 10800000).toISOString(),
    severity: 'MEDIUM',
    incident_type: 'ANOMALY',
    source_ip: '172.16.0.25',
    description: 'Unusual network traffic pattern detected',
    status: 'RESOLVED',
    assigned_to: 'admin',
    resolved_at: new Date(Date.now() - 3600000).toISOString()
  }
];

const mockTraffic = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 60000).toISOString(),
    source_ip: '192.168.1.10',
    dest_ip: '8.8.8.8',
    source_port: 54321,
    dest_port: 53,
    protocol: 'UDP',
    packet_size: 64
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 120000).toISOString(),
    source_ip: '192.168.1.15',
    dest_ip: '1.1.1.1',
    source_port: 443,
    dest_port: 443,
    protocol: 'TCP',
    packet_size: 1500
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 180000).toISOString(),
    source_ip: '10.0.0.100',
    dest_ip: '192.168.1.1',
    source_port: 80,
    dest_port: 8080,
    protocol: 'HTTP',
    packet_size: 2048
  }
];

const mockStats = {
  total_incidents: 15,
  open_incidents: 3,
  critical_incidents: 1,
  packets_last_hour: 1247,
  top_source_ips: [
    { ip: '192.168.1.10', count: 45 },
    { ip: '10.0.0.100', count: 32 },
    { ip: '172.16.0.25', count: 28 }
  ],
  incident_trends: [
    { date: '2026-01-01', count: 2 },
    { date: '2026-01-02', count: 4 },
    { date: '2026-01-03', count: 1 },
    { date: '2026-01-04', count: 3 },
    { date: '2026-01-05', count: 2 },
    { date: '2026-01-06', count: 3 }
  ]
};

const mockAlerts = {
  alerts: [
    {
      id: 1,
      type: 'SECURITY',
      message: 'Port scan detected from 192.168.1.100',
      timestamp: new Date(Date.now() - 300000).toISOString(),
      severity: 'HIGH'
    },
    {
      id: 2,
      type: 'NETWORK',
      message: 'High bandwidth usage detected',
      timestamp: new Date(Date.now() - 600000).toISOString(),
      severity: 'MEDIUM'
    }
  ]
};

// Mock API functions
export const mockApi = {
  getDashboardStats: () => Promise.resolve(mockStats),
  getIncidents: (params = {}) => {
    let filtered = [...mockIncidents];
    if (params.severity) {
      filtered = filtered.filter(i => i.severity === params.severity);
    }
    if (params.status) {
      filtered = filtered.filter(i => i.status === params.status);
    }
    return Promise.resolve(filtered.slice(0, params.limit || 50));
  },
  getTraffic: (params = {}) => {
    let filtered = [...mockTraffic];
    if (params.source_ip) {
      filtered = filtered.filter(t => t.source_ip === params.source_ip);
    }
    return Promise.resolve(filtered.slice(0, params.limit || 100));
  },
  getLiveAlerts: () => Promise.resolve(mockAlerts),
  acknowledgeIncident: (id) => Promise.resolve({ message: 'Incident acknowledged successfully' }),
  resolveIncident: (id) => Promise.resolve({ message: 'Incident resolved successfully' })
};

export default mockApi;