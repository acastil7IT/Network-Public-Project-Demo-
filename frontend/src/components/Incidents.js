import React, { useState, useEffect } from 'react';
import { Table, Tag, Button, Space, Modal, Select, message } from 'antd';
import { ExclamationCircleOutlined, CheckOutlined } from '@ant-design/icons';
import axios from 'axios';
import moment from 'moment';

const { Option } = Select;

const Incidents = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    severity: null,
    status: null
  });

  useEffect(() => {
    fetchIncidents();
  }, [filters]);

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (filters.severity) params.append('severity', filters.severity);
      if (filters.status) params.append('status', filters.status);

      const response = await axios.get(`http://localhost:8001/api/incidents?${params}`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      setIncidents(response.data);
    } catch (error) {
      message.error('Failed to fetch incidents');
      console.error('Incidents fetch error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAcknowledge = async (incidentId) => {
    try {
      await axios.post(`http://localhost:8001/api/incidents/${incidentId}/acknowledge`, {}, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      message.success('Incident acknowledged');
      fetchIncidents();
    } catch (error) {
      message.error('Failed to acknowledge incident');
    }
  };

  const handleResolve = async (incidentId) => {
    Modal.confirm({
      title: 'Resolve Incident',
      icon: <ExclamationCircleOutlined />,
      content: 'Are you sure you want to resolve this incident?',
      onOk: async () => {
        try {
          await axios.post(`http://localhost:8001/api/incidents/${incidentId}/resolve`, {}, {
            headers: {
              'Authorization': 'Bearer demo-token'
            }
          });
          message.success('Incident resolved');
          fetchIncidents();
        } catch (error) {
          message.error('Failed to resolve incident');
        }
      }
    });
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

  const getStatusColor = (status) => {
    const colors = {
      'OPEN': 'red',
      'ACKNOWLEDGED': 'orange',
      'RESOLVED': 'green'
    };
    return colors[status] || 'default';
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 80,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => moment(date).format('YYYY-MM-DD HH:mm'),
      sorter: (a, b) => new Date(a.created_at) - new Date(b.created_at),
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity) => (
        <Tag color={getSeverityColor(severity)}>{severity}</Tag>
      ),
      filters: [
        { text: 'Critical', value: 'CRITICAL' },
        { text: 'High', value: 'HIGH' },
        { text: 'Medium', value: 'MEDIUM' },
        { text: 'Low', value: 'LOW' },
      ],
    },
    {
      title: 'Type',
      dataIndex: 'incident_type',
      key: 'incident_type',
    },
    {
      title: 'Source IP',
      dataIndex: 'source_ip',
      key: 'source_ip',
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status) => (
        <Tag color={getStatusColor(status)}>{status}</Tag>
      ),
      filters: [
        { text: 'Open', value: 'OPEN' },
        { text: 'Acknowledged', value: 'ACKNOWLEDGED' },
        { text: 'Resolved', value: 'RESOLVED' },
      ],
    },
    {
      title: 'Assigned To',
      dataIndex: 'assigned_to',
      key: 'assigned_to',
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space size="middle">
          {record.status === 'OPEN' && (
            <Button
              size="small"
              type="primary"
              icon={<ExclamationCircleOutlined />}
              onClick={() => handleAcknowledge(record.id)}
            >
              Acknowledge
            </Button>
          )}
          {record.status !== 'RESOLVED' && (
            <Button
              size="small"
              type="primary"
              danger
              icon={<CheckOutlined />}
              onClick={() => handleResolve(record.id)}
            >
              Resolve
            </Button>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Space>
          <Select
            placeholder="Filter by Severity"
            style={{ width: 150 }}
            allowClear
            onChange={(value) => setFilters({ ...filters, severity: value })}
          >
            <Option value="CRITICAL">Critical</Option>
            <Option value="HIGH">High</Option>
            <Option value="MEDIUM">Medium</Option>
            <Option value="LOW">Low</Option>
          </Select>
          <Select
            placeholder="Filter by Status"
            style={{ width: 150 }}
            allowClear
            onChange={(value) => setFilters({ ...filters, status: value })}
          >
            <Option value="OPEN">Open</Option>
            <Option value="ACKNOWLEDGED">Acknowledged</Option>
            <Option value="RESOLVED">Resolved</Option>
          </Select>
          <Button onClick={fetchIncidents}>Refresh</Button>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={incidents}
        loading={loading}
        rowKey="id"
        pagination={{
          pageSize: 20,
          showSizeChanger: true,
          showQuickJumper: true,
        }}
        scroll={{ x: 1200 }}
      />
    </div>
  );
};

export default Incidents;