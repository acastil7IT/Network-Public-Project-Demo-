import React, { useState, useEffect } from 'react';
import { Card, List, Tag, Badge, Button, Space, Alert } from 'antd';
import { AlertOutlined, ReloadOutlined } from '@ant-design/icons';
import axios from 'axios';
import moment from 'moment';

const LiveAlerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  useEffect(() => {
    fetchLiveAlerts();
    
    let interval;
    if (autoRefresh) {
      interval = setInterval(fetchLiveAlerts, 5000); // Refresh every 5 seconds
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);

  const fetchLiveAlerts = async () => {
    try {
      const response = await axios.get('http://localhost:8001/api/alerts/live', {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      setAlerts(response.data.alerts || []);
    } catch (error) {
      console.error('Live alerts fetch error:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'LOW': 'green',
      'MEDIUM': 'orange',
      'HIGH': 'red',
      'CRITICAL': 'purple'
    };
    return colors[severity] || 'default';
  };

  const getThreatTypeIcon = (threatType) => {
    return <AlertOutlined style={{ color: '#ff4d4f' }} />;
  };

  const formatTimestamp = (timestamp) => {
    return moment(timestamp).format('YYYY-MM-DD HH:mm:ss');
  };

  const getConfidenceLevel = (confidence) => {
    if (confidence >= 0.8) return { text: 'High', color: 'red' };
    if (confidence >= 0.6) return { text: 'Medium', color: 'orange' };
    return { text: 'Low', color: 'green' };
  };

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Space>
          <Button 
            type="primary"
            icon={<ReloadOutlined />}
            onClick={fetchLiveAlerts}
            loading={loading}
          >
            Refresh Now
          </Button>
          <Button
            type={autoRefresh ? 'primary' : 'default'}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            {autoRefresh ? 'Auto-Refresh ON' : 'Auto-Refresh OFF'}
          </Button>
          <Badge 
            count={alerts.length} 
            style={{ backgroundColor: '#52c41a' }}
          >
            <span>Live Alerts</span>
          </Badge>
        </Space>
      </div>

      {alerts.length === 0 && !loading && (
        <Alert
          message="No Recent Alerts"
          description="No security alerts have been detected in the last few minutes."
          type="info"
          showIcon
        />
      )}

      <List
        loading={loading}
        dataSource={alerts}
        renderItem={(alert, index) => {
          const confidenceLevel = getConfidenceLevel(alert.confidence);
          
          return (
            <List.Item key={index}>
              <Card 
                size="small" 
                style={{ width: '100%' }}
                title={
                  <Space>
                    {getThreatTypeIcon(alert.threat_type)}
                    <span>{alert.threat_type.replace(/_/g, ' ')}</span>
                    <Tag color={getSeverityColor(alert.severity)}>
                      {alert.severity}
                    </Tag>
                  </Space>
                }
                extra={
                  <Space>
                    <Tag color={confidenceLevel.color}>
                      {confidenceLevel.text} Confidence
                    </Tag>
                    <span style={{ fontSize: '12px', color: '#666' }}>
                      {formatTimestamp(alert.timestamp)}
                    </span>
                  </Space>
                }
              >
                <div style={{ marginBottom: 8 }}>
                  <strong>Source IP:</strong> {alert.source_ip}
                </div>
                <div style={{ marginBottom: 8 }}>
                  <strong>Description:</strong> {alert.description}
                </div>
                <div style={{ marginBottom: 8 }}>
                  <strong>Confidence Score:</strong> {(alert.confidence * 100).toFixed(1)}%
                </div>
                
                {alert.raw_data && (
                  <details style={{ marginTop: 8 }}>
                    <summary style={{ cursor: 'pointer', color: '#1890ff' }}>
                      Raw Data
                    </summary>
                    <pre style={{ 
                      background: '#f5f5f5', 
                      padding: '8px', 
                      marginTop: '8px',
                      fontSize: '12px',
                      overflow: 'auto'
                    }}>
                      {JSON.stringify(alert.raw_data, null, 2)}
                    </pre>
                  </details>
                )}
              </Card>
            </List.Item>
          );
        }}
      />
    </div>
  );
};

export default LiveAlerts;