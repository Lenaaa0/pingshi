import React from 'react';
import { Layout, Typography } from 'antd';
import { SafetyCertificateOutlined } from '@ant-design/icons';

const { Header } = Layout;
const { Title } = Typography;

const AppHeader: React.FC = () => {
  return (
    <Header style={{ display: 'flex', alignItems: 'center' }}>
      <div style={{ display: 'flex', alignItems: 'center', color: 'white' }}>
        <SafetyCertificateOutlined style={{ fontSize: 24, marginRight: 12 }} />
        <Title level={4} style={{ color: 'white', margin: 0 }}>
          安全扫描系统
        </Title>
      </div>
    </Header>
  );
};

export default AppHeader; 