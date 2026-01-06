import React, { useState, useEffect } from 'react';
import { Table, Input, Button, Space, Tag } from 'antd';
import { SearchOutlined, ReloadOutlined } from '@ant-design/icons';
import axios from 'axios';
import moment from 'moment';

const NetworkTraffic = () => {
  const [traffic, setTraffic] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchIP, setSearchIP] = useState('');

  useEffect(() => {
    fetchTraffic();
    const interval = setInterval(fetchTraffic, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchTraffic = async (sourceIP = null) => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (sourceIP) params.append('source_ip', sourceIP);
      params.append('limit', '200');

      const response = await axios.get(`http://localhost:8001/api/traffic?${params}`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      setTraffic(response.data);
    } catch (error) {
      console.error('Traffic fetch error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = () => {
    fetchTraffic(searchIP || null);
  };

  const getProtocolColor = (protocol) => {
    const colors = {
      'TCP': 'blue',
      'UDP': 'green',
      'ICMP': 'orange',
      'OTHER': 'default'
    };
    return colors[protocol] || 'default';
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const columns = [
    {
      title: 'Timestamp',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (date) => moment(date).format('HH:mm:ss'),
      width: 100,
    },
    {
      title: 'Source IP',
      dataIndex: 'source_ip',
      key: 'source_ip',
      width: 120,
    },
    {
      title: 'Source Port',
      dataIndex: 'source_port',
      key: 'source_port',
      width: 100,
    },
    {
      title: 'Destination IP',
      dataIndex: 'dest_ip',
      key: 'dest_ip',
      width: 120,
    },
    {
      title: 'Dest Port',
      dataIndex: 'dest_port',
      key: 'dest_port',
      width: 100,
    },
    {
      title: 'Protocol',
      dataIndex: 'protocol',
      key: 'protocol',
      render: (protocol) => (
        <Tag color={getProtocolColor(protocol)}>{protocol}</Tag>
      ),
      width: 80,
    },
    {
      title: 'Size',
      dataIndex: 'packet_size',
      key: 'packet_size',
      render: (size) => formatBytes(size),
      sorter: (a, b) => a.packet_size - b.packet_size,
      width: 80,
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 16 }}>
        <Space>
          <Input
            placeholder="Search by Source IP"
            value={searchIP}
            onChange={(e) => setSearchIP(e.target.value)}
            onPressEnter={handleSearch}
            style={{ width: 200 }}
          />
          <Button 
            type="primary" 
            icon={<SearchOutlined />}
            onClick={handleSearch}
          >
            Search
          </Button>
          <Button 
            icon={<ReloadOutlined />}
            onClick={() => {
              setSearchIP('');
              fetchTraffic();
            }}
          >
            Clear & Refresh
          </Button>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={traffic}
        loading={loading}
        rowKey="id"
        pagination={{
          pageSize: 50,
          showSizeChanger: true,
          showQuickJumper: true,
          showTotal: (total, range) => 
            `${range[0]}-${range[1]} of ${total} packets`,
        }}
        scroll={{ x: 800 }}
        size="small"
      />
    </div>
  );
};

export default NetworkTraffic;