import React, { useState } from 'react';
import { Card, Input, Button, Typography, Alert } from 'antd';
import { ScanOutlined } from '@ant-design/icons';

const { Title, Paragraph } = Typography;

interface PortScanFormProps {
  onScan: (target: string) => void;
  scanning: boolean;
}

const PortScanForm: React.FC<PortScanFormProps> = ({ onScan, scanning }) => {
  const [target, setTarget] = useState('');
  
  return (
    <div>
      <Card style={{ marginBottom: 24 }}>
        <Title level={4}>端口扫描</Title>
        <Paragraph>
          端口扫描可以检测目标系统开放的网络端口，识别运行的服务和版本信息。
        </Paragraph>
        
        <Alert
          message="使用说明"
          description="输入目标域名或IP地址，点击开始扫描按钮。扫描过程可能需要几分钟时间，请耐心等待。"
          type="info"
          showIcon
          style={{ marginBottom: 24 }}
        />
        
        <div style={{ display: 'flex', gap: 16 }}>
          <Input
            placeholder="输入目标域名或IP (例如: example.com 或 192.168.1.1)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            style={{ flex: 1 }}
            size="large"
          />
          <Button
            type="primary"
            icon={<ScanOutlined />}
            loading={scanning}
            onClick={() => onScan(target)}
            size="large"
          >
            开始扫描
          </Button>
        </div>
      </Card>
      
      <Card title="端口扫描说明">
        <Paragraph>
          端口扫描是一种网络安全评估技术，用于检查目标系统上开放的TCP和UDP端口。通过端口扫描，可以：
        </Paragraph>
        <ul>
          <li>识别目标系统上运行的网络服务</li>
          <li>发现潜在的安全漏洞</li>
          <li>检测未经授权的服务</li>
          <li>评估网络安全策略的有效性</li>
        </ul>
        <Paragraph>
          <strong>注意：</strong> 请确保您有权限对目标系统进行扫描。未经授权的端口扫描可能违反法律法规。
        </Paragraph>
      </Card>
    </div>
  );
};

export default PortScanForm; 