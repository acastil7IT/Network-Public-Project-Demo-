import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Button, Select, Input, Table, Tag, Progress, Alert, Tabs } from 'antd';
import { 
  ScanOutlined, 
  BugOutlined, 
  GlobalOutlined,
  SecurityScanOutlined,
  PlayCircleOutlined,
  StopOutlined
} from '@ant-design/icons';
import axios from 'axios';

const { Option } = Select;
const { TabPane } = Tabs;

const AdvancedScanning = () => {
  const [scanResults, setScanResults] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [selectedTarget, setSelectedTarget] = useState('localhost');
  const [scanType, setScanType] = useState('comprehensive');
  const [recentScans, setRecentScans] = useState([]);

  const scanTypes = [
    { value: 'comprehensive', label: 'Comprehensive Scan', description: 'Full port scan + vulnerability assessment' },
    { value: 'stealth', label: 'Stealth Scan', description: 'SYN scan to avoid detection' },
    { value: 'fast', label: 'Fast Scan', description: 'Quick scan of common ports' },
    { value: 'vulnerability', label: 'Vulnerability Scan', description: 'Web vulnerability assessment' },
    { value: 'network_discovery', label: 'Network Discovery', description: 'Find live hosts on network' }
  ];

  const predefinedTargets = [
    { value: 'localhost', label: 'Localhost (Safe)', description: 'Scan local system' },
    { value: 'test-targets', label: 'Test Environment', description: 'Controlled vulnerable environment' },
    { value: '192.168.1.0/24', label: 'Local Network', description: 'Scan local network range' }
  ];

  const startAdvancedScan = async () => {
    setScanning(true);
    setScanProgress(0);
    
    // Demo version - uses mock data only for public safety
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + 10;
      });
    }, 500);

    // Simulate realistic scan time
    setTimeout(() => {
      clearInterval(progressInterval);
      setScanProgress(100);
      
      // Generate realistic mock results
      const mockResults = generateMockScanResults(scanType, selectedTarget);
      setScanResults(mockResults);
      
      // Add to recent scans
      const newScan = {
        id: Date.now(),
        target: selectedTarget,
        type: scanType,
        timestamp: new Date().toISOString(),
        findings: mockResults.length,
        status: 'completed'
      };
      setRecentScans(prev => [newScan, ...prev.slice(0, 4)]);
      
      setTimeout(() => {
        setScanning(false);
        setScanProgress(0);
      }, 1000);
    }, 3000);
  };

  const generateMockScanResults = (type, target) => {
    const baseResults = [
      {
        key: '1',
        finding: 'Open Port: 80/tcp (HTTP)',
        severity: 'INFO',
        tool: 'Nmap',
        description: 'HTTP service detected on port 80'
      },
      {
        key: '2', 
        finding: 'Open Port: 443/tcp (HTTPS)',
        severity: 'INFO',
        tool: 'Nmap',
        description: 'HTTPS service detected on port 443'
      }
    ];

    if (type === 'comprehensive') {
      return [
        ...baseResults,
        {
          key: '3',
          finding: 'SSH Service: OpenSSH 8.2',
          severity: 'LOW',
          tool: 'Nmap',
          description: 'SSH service version detected'
        },
        {
          key: '4',
          finding: 'Web Server: Apache/2.4.41',
          severity: 'INFO',
          tool: 'Nmap',
          description: 'Apache web server detected'
        },
        {
          key: '5',
          finding: 'OS Detection: Linux 5.4',
          severity: 'INFO',
          tool: 'Nmap',
          description: 'Operating system fingerprint detected'
        }
      ];
    } else if (type === 'vulnerability') {
      return [
        ...baseResults,
        {
          key: '3',
          finding: 'Directory Listing Enabled',
          severity: 'MEDIUM',
          tool: 'Nikto',
          description: 'Server allows directory browsing'
        },
        {
          key: '4',
          finding: 'Missing Security Headers',
          severity: 'LOW',
          tool: 'Nikto',
          description: 'X-Frame-Options header not set'
        },
        {
          key: '5',
          finding: 'Admin Panel Found: /admin',
          severity: 'HIGH',
          tool: 'Dirb',
          description: 'Administrative interface discovered'
        }
      ];
    }

    return baseResults;
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'INFO': 'blue',
      'LOW': 'green', 
      'MEDIUM': 'orange',
      'HIGH': 'red',
      'CRITICAL': 'purple'
    };
    return colors[severity] || 'default';
  };

  const scanResultColumns = [
    {
      title: 'Finding',
      dataIndex: 'finding',
      key: 'finding',
      width: '30%'
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity) => (
        <Tag color={getSeverityColor(severity)}>{severity}</Tag>
      ),
      width: '15%'
    },
    {
      title: 'Tool',
      dataIndex: 'tool',
      key: 'tool',
      width: '15%'
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      width: '40%'
    }
  ];

  const recentScansColumns = [
    {
      title: 'Target',
      dataIndex: 'target',
      key: 'target'
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type'
    },
    {
      title: 'Findings',
      dataIndex: 'findings',
      key: 'findings'
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status) => (
        <Tag color={status === 'completed' ? 'green' : 'blue'}>{status}</Tag>
      )
    }
  ];

  return (
    <div>
      <Alert
        message="Advanced Security Scanning"
        description="Professional security tools integration: Nmap, Wireshark, Nikto, and more. Only scan systems you own or have permission to test."
        type="info"
        showIcon
        style={{ marginBottom: 24 }}
      />

      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={8}>
          <Card title="🎯 Scan Configuration" size="small">
            <div style={{ marginBottom: 16 }}>
              <label>Target:</label>
              <Select
                value={selectedTarget}
                onChange={setSelectedTarget}
                style={{ width: '100%', marginTop: 8 }}
              >
                {predefinedTargets.map(target => (
                  <Option key={target.value} value={target.value}>
                    {target.label}
                  </Option>
                ))}
              </Select>
              <Input
                placeholder="Or enter custom target"
                style={{ marginTop: 8 }}
                onChange={(e) => setSelectedTarget(e.target.value)}
              />
            </div>

            <div style={{ marginBottom: 16 }}>
              <label>Scan Type:</label>
              <Select
                value={scanType}
                onChange={setScanType}
                style={{ width: '100%', marginTop: 8 }}
              >
                {scanTypes.map(type => (
                  <Option key={type.value} value={type.value}>
                    {type.label}
                  </Option>
                ))}
              </Select>
            </div>

            <Button
              type="primary"
              icon={scanning ? <StopOutlined /> : <PlayCircleOutlined />}
              onClick={startAdvancedScan}
              loading={scanning}
              block
              size="large"
            >
              {scanning ? 'Scanning...' : 'Start Advanced Scan'}
            </Button>

            {scanning && (
              <div style={{ marginTop: 16 }}>
                <Progress percent={scanProgress} status="active" />
                <p style={{ textAlign: 'center', marginTop: 8 }}>
                  Running {scanType} scan on {selectedTarget}
                </p>
              </div>
            )}
          </Card>
        </Col>

        <Col span={16}>
          <Card title="📊 Scan Statistics" size="small">
            <Row gutter={16}>
              <Col span={6}>
                <div style={{ textAlign: 'center' }}>
                  <ScanOutlined style={{ fontSize: 24, color: '#1890ff' }} />
                  <div style={{ fontSize: 20, fontWeight: 'bold' }}>
                    {recentScans.length}
                  </div>
                  <div>Total Scans</div>
                </div>
              </Col>
              <Col span={6}>
                <div style={{ textAlign: 'center' }}>
                  <BugOutlined style={{ fontSize: 24, color: '#f5222d' }} />
                  <div style={{ fontSize: 20, fontWeight: 'bold' }}>
                    {scanResults.filter(r => r.severity === 'HIGH' || r.severity === 'CRITICAL').length}
                  </div>
                  <div>High Risk</div>
                </div>
              </Col>
              <Col span={6}>
                <div style={{ textAlign: 'center' }}>
                  <GlobalOutlined style={{ fontSize: 24, color: '#52c41a' }} />
                  <div style={{ fontSize: 20, fontWeight: 'bold' }}>
                    {scanResults.filter(r => r.finding.includes('Open Port')).length}
                  </div>
                  <div>Open Ports</div>
                </div>
              </Col>
              <Col span={6}>
                <div style={{ textAlign: 'center' }}>
                  <SecurityScanOutlined style={{ fontSize: 24, color: '#722ed1' }} />
                  <div style={{ fontSize: 20, fontWeight: 'bold' }}>
                    {scanResults.length}
                  </div>
                  <div>Total Findings</div>
                </div>
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>

      <Tabs defaultActiveKey="results">
        <TabPane tab="🔍 Scan Results" key="results">
          <Card title="Latest Scan Results">
            {scanResults.length > 0 ? (
              <Table
                columns={scanResultColumns}
                dataSource={scanResults}
                pagination={false}
                size="small"
              />
            ) : (
              <div style={{ textAlign: 'center', padding: 40 }}>
                <ScanOutlined style={{ fontSize: 48, color: '#d9d9d9' }} />
                <p style={{ marginTop: 16, color: '#999' }}>
                  No scan results yet. Start a scan to see findings here.
                </p>
              </div>
            )}
          </Card>
        </TabPane>

        <TabPane tab="📋 Recent Scans" key="history">
          <Card title="Scan History">
            <Table
              columns={recentScansColumns}
              dataSource={recentScans}
              pagination={false}
              size="small"
            />
          </Card>
        </TabPane>

        <TabPane tab="🛠️ Tools" key="tools">
          <Card title="Available Security Tools">
            <Row gutter={16}>
              <Col span={8}>
                <Card size="small" title="Nmap">
                  <p>Network discovery and port scanning</p>
                  <Tag color="green">Active</Tag>
                </Card>
              </Col>
              <Col span={8}>
                <Card size="small" title="Wireshark">
                  <p>Packet capture and analysis</p>
                  <Tag color="green">Active</Tag>
                </Card>
              </Col>
              <Col span={8}>
                <Card size="small" title="Nikto">
                  <p>Web vulnerability scanner</p>
                  <Tag color="green">Active</Tag>
                </Card>
              </Col>
            </Row>
            <Row gutter={16} style={{ marginTop: 16 }}>
              <Col span={8}>
                <Card size="small" title="Dirb">
                  <p>Directory enumeration</p>
                  <Tag color="green">Active</Tag>
                </Card>
              </Col>
              <Col span={8}>
                <Card size="small" title="Masscan">
                  <p>High-speed port scanner</p>
                  <Tag color="green">Active</Tag>
                </Card>
              </Col>
              <Col span={8}>
                <Card size="small" title="SQLMap">
                  <p>SQL injection testing</p>
                  <Tag color="green">Active</Tag>
                </Card>
              </Col>
            </Row>
          </Card>
        </TabPane>
      </Tabs>
    </div>
  );
};

export default AdvancedScanning;