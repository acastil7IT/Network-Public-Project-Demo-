import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Layout, Menu, theme } from 'antd';
import {
  DashboardOutlined,
  AlertOutlined,
  GlobalOutlined,
  SettingOutlined,
  SecurityScanOutlined,
  BugOutlined
} from '@ant-design/icons';

import Dashboard from './components/Dashboard';
import Incidents from './components/Incidents';
import NetworkTraffic from './components/NetworkTraffic';
import LiveAlerts from './components/LiveAlerts';
import AdvancedScanning from './components/AdvancedScanning';

import './App.css';

const { Header, Sider, Content } = Layout;

function App() {
  const {
    token: { colorBgContainer },
  } = theme.useToken();

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: 'Dashboard',
    },
    {
      key: '/incidents',
      icon: <AlertOutlined />,
      label: 'Security Incidents',
    },
    {
      key: '/traffic',
      icon: <GlobalOutlined />,
      label: 'Network Traffic',
    },
    {
      key: '/alerts',
      icon: <SecurityScanOutlined />,
      label: 'Live Alerts',
    },
    {
      key: '/advanced-scanning',
      icon: <BugOutlined />,
      label: 'Advanced Scanning',
    },
  ];

  return (
    <Router>
      <Layout style={{ minHeight: '100vh' }}>
        <Sider
          breakpoint="lg"
          collapsedWidth="0"
          style={{
            background: colorBgContainer,
          }}
        >
        <div className="logo">
            <SecurityScanOutlined style={{ fontSize: '24px', color: '#1890ff' }} />
            <span style={{ marginLeft: '8px', fontWeight: 'bold' }}>SecureNet</span>
          </div>
          <Menu
            theme="light"
            mode="inline"
            defaultSelectedKeys={['/']}
            items={menuItems}
            onClick={({ key }) => {
              window.location.pathname = key;
            }}
          />
        </Sider>
        <Layout>
          <Header
            style={{
              padding: 0,
              background: colorBgContainer,
              borderBottom: '1px solid #f0f0f0',
            }}
          >
            <div style={{ 
              padding: '0 24px', 
              fontSize: '18px', 
              fontWeight: 'bold',
              color: '#1890ff'
            }}>
              Network Security Monitoring Platform
            </div>
          </Header>
          <Content
            style={{
              margin: '24px 16px',
              padding: 24,
              minHeight: 280,
              background: colorBgContainer,
            }}
          >
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/traffic" element={<NetworkTraffic />} />
              <Route path="/alerts" element={<LiveAlerts />} />
              <Route path="/advanced-scanning" element={<AdvancedScanning />} />
            </Routes>
          </Content>
        </Layout>
      </Layout>
    </Router>
  );
}

export default App;