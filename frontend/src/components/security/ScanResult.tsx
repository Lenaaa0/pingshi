import React from 'react';
import { 
  Modal, 
  Typography, 
  Table, 
  Card, 
  Tag, 
  Button,
  Descriptions,
  Progress
} from 'antd';
import { ScanResult as ScanResultType } from '../../models/types';
import { formatTime } from '../../utils/formatters';

// 只解构实际使用的组件
const { Text } = Typography;

interface ScanResultProps {
  result: ScanResultType | null;
  visible: boolean;
  onClose: () => void;
} 

const ScanResultComponent: React.FC<ScanResultProps> = ({ result, visible, onClose }) => {
  if (!result) return null;
  
  // 漏洞严重性标签颜色映射
  const severityColorMap = {
    high: 'red',
    medium: 'orange',
    low: 'blue'
  };
  
  // 漏洞表格列定义
  const vulnerabilityColumns = [
    {
      title: '漏洞名称',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      render: (severity: string) => (
        <Tag color={severityColorMap[severity as keyof typeof severityColorMap] || 'default'}>
          {severity === 'high' ? '高危' : severity === 'medium' ? '中危' : '低危'}
        </Tag>
      ),
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
    },
    {
      title: '修复建议',
      dataIndex: 'recommendation',
      key: 'recommendation',
    },
  ];
  
  // 端口表格列定义
  const portColumns = [
    {
      title: '端口',
      dataIndex: 'port',
      key: 'port',
    },
    {
      title: '服务',
      dataIndex: 'service',
      key: 'service',
    },
    {
      title: '状态',
      dataIndex: 'state',
      key: 'state',
      render: (state: string) => (
        <Tag color={state === 'open' ? 'green' : state === 'filtered' ? 'orange' : 'default'}>
          {state}
        </Tag>
      ),
    },
    {
      title: '版本',
      dataIndex: 'version',
      key: 'version',
      render: (version: string) => version || '未知',
    },
  ];
  
  return (
    <Modal
      title={`扫描结果: ${result.target}`}
      open={visible}
      onCancel={onClose}
      width={800}
      footer={[
        <Button key="close" onClick={onClose}>
          关闭
        </Button>,
        <Button key="download" type="primary">
          下载报告
        </Button>,
      ]}
    >
      <Card style={{ marginBottom: 16 }}>
        <Descriptions title="扫描信息" bordered column={2}>
          <Descriptions.Item label="目标">{result.target}</Descriptions.Item>
          <Descriptions.Item label="扫描类型">
            {result.scan_type === 'port' ? '端口扫描' : '漏洞扫描'}
          </Descriptions.Item>
          <Descriptions.Item label="开始时间">{formatTime(result.start_time)}</Descriptions.Item>
          <Descriptions.Item label="结束时间">{formatTime(result.end_time)}</Descriptions.Item>
          <Descriptions.Item label="状态">
            <Tag color={result.status === 'completed' ? 'success' : 'error'}>
              {result.status === 'completed' ? '已完成' : '失败'}
            </Tag>
          </Descriptions.Item>
          {result.risk_score !== undefined && (
            <Descriptions.Item label="风险评分">
              <Progress 
                type="circle" 
                percent={result.risk_score} 
                width={80}
                status={
                  result.risk_score > 70 ? 'exception' : 
                  result.risk_score > 40 ? 'normal' : 'success'
                }
              />
            </Descriptions.Item>
          )}
        </Descriptions>
      </Card>
      
      {/* 漏洞信息 */}
      {result.vulnerabilities && result.vulnerabilities.length > 0 && (
        <Card title="发现的漏洞" style={{ marginBottom: 16 }}>
          <Table 
            dataSource={result.vulnerabilities} 
            columns={vulnerabilityColumns}
            rowKey="name"
            pagination={false}
          />
        </Card>
      )}
      
      {/* 开放端口信息 */}
      {result.open_ports && result.open_ports.length > 0 && (
        <Card title="开放的端口">
          <Table 
            dataSource={result.open_ports} 
            columns={portColumns}
            rowKey="port"
            pagination={false}
          />
        </Card>
      )}
    </Modal>
  );
};

export default ScanResultComponent; 