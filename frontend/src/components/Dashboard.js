import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Statistic, Table, Alert } from 'antd';
import { 
  AlertOutlined, 
  GlobalOutlined, 
  SecurityScanOutlined,
  ExclamationCircleOutlined 
} from '@ant-design/icons';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import mockApi from '../services/mockApi';

const Dashboard = () => {
  const [stats, setStats] = useState({
    total_incidents: 0,
    open_incidents: 0,
    critical_incidents: 0,
    packets_last_hour: 0,
    top_source_ips: [],
    incident_trends: []
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardStats();
    const interval = setInterval(fetchDashboardStats, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardStats = async () => {
    try {
      const response = await mockApi.getDashboardStats();
      setStats(response);
      setError(null);
    } catch (err) {
      setError('Failed to fetch dashboard statistics');
      console.error('Dashboard stats error:', err);
    } finally {
      setLoading(false);
    }
  };

  const topIPColumns = [
    {
      title: 'Source IP',
      dataIndex: 'ip',
      key: 'ip',
    },
    {
      title: 'Packet Count',
      dataIndex: 'count',
      key: 'count',
      sorter: (a, b) => a.count - b.count,
    },
  ];

  return (
    <div>
      {error && (
        <Alert
          message="Error"
          description={error}
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}

      {/* Key Metrics */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="Total Incidents"
              value={stats.total_incidents}
              prefix={<AlertOutlined />}
              loading={loading}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Open Incidents"
              value={stats.open_incidents}
              prefix={<ExclamationCircleOutlined />}
              valueStyle={{ color: '#cf1322' }}
              loading={loading}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Critical Incidents"
              value={stats.critical_incidents}
              prefix={<SecurityScanOutlined />}
              valueStyle={{ color: '#722ed1' }}
              loading={loading}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Packets (Last Hour)"
              value={stats.packets_last_hour}
              prefix={<GlobalOutlined />}
              loading={loading}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={16}>
        {/* Incident Trends Chart */}
        <Col span={16}>
          <Card title="Incident Trends (Last 7 Days)" loading={loading}>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={stats.incident_trends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="count" 
                  stroke="#1890ff" 
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </Col>

        {/* Top Source IPs */}
        <Col span={8}>
          <Card title="Top Source IPs (24h)" loading={loading}>
            <Table
              dataSource={stats.top_source_ips}
              columns={topIPColumns}
              pagination={false}
              size="small"
              rowKey="ip"
            />
          </Card>
        </Col>
      </Row>

      {/* System Status */}
      <Row gutter={16} style={{ marginTop: 24 }}>
        <Col span={24}>
          <Card title="System Status">
            <Row gutter={16}>
              <Col span={6}>
                <Statistic
                  title="Traffic Analyzer"
                  value="Online"
                  valueStyle={{ color: '#3f8600' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="Threat Detector"
                  value="Online"
                  valueStyle={{ color: '#3f8600' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="Database"
                  value="Online"
                  valueStyle={{ color: '#3f8600' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="Alert System"
                  value="Online"
                  valueStyle={{ color: '#3f8600' }}
                />
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;