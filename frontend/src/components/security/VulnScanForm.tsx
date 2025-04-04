import React, { useState } from 'react';
import { Card, Input, Button, Typography, Alert } from 'antd';
import { BugOutlined } from '@ant-design/icons';

const { Title, Paragraph } = Typography;

interface VulnScanFormProps {
  onScan: (target: string) => void;
  scanning: boolean;
}

const VulnScanForm: React.FC<VulnScanFormProps> = ({ onScan, scanning }) => {
  const [target, setTarget] = useState('');
  
  return (
    <div>
      <Card style={{ marginBottom: 24 }}>
        <Title level={4}>漏洞扫描</Title>
        <Paragraph>
          漏洞扫描可以检测目标系统的安全漏洞，提供详细的漏洞信息和修复建议。
        </Paragraph>
        
        <Alert
          message="使用说明"
          description="输入目标域名或IP地址，点击开始扫描按钮。漏洞扫描过程可能需要较长时间，请耐心等待。"
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
            danger
            icon={<BugOutlined />}
            loading={scanning}
            onClick={() => onScan(target)}
            size="large"
          >
            开始扫描
          </Button>
        </div>
      </Card>
      
      <Card title="漏洞扫描说明">
        <Paragraph>
          漏洞扫描是一种安全评估技术，用于识别目标系统中的安全漏洞。通过漏洞扫描，可以：
        </Paragraph>
        <ul>
          <li>发现系统中的安全漏洞</li>
          <li>评估漏洞的严重程度</li>
          <li>获取漏洞修复建议</li>
          <li>提高系统的整体安全性</li>
        </ul>
        <Paragraph>
          <strong>注意：</strong> 请确保您有权限对目标系统进行扫描。未经授权的漏洞扫描可能违反法律法规。
        </Paragraph>
      </Card>
    </div>
  );
};

export default VulnScanForm; 