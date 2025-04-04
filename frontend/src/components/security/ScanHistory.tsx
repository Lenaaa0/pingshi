import React from 'react';
import { Table, Tag, Button, Empty, Card } from 'antd';
import { EyeOutlined } from '@ant-design/icons';
import { ScanResult } from '../../models/types';
import { formatTime } from '../../utils/formatters';

interface ScanHistoryProps {
  scanResults: ScanResult[];
  loading: boolean;
  onViewResult: (result: ScanResult) => void;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ 
  scanResults, 
  loading, 
  onViewResult 
}) => {
  const getStatusTag = (status: string) => {
    switch (status) {
      case 'completed':
        return <Tag color="success">已完成</Tag>;
      case 'running':
        return <Tag color="processing">进行中</Tag>;
      case 'failed':
        return <Tag color="error">失败</Tag>;
      default:
        return <Tag color="default">未知</Tag>;
    }
  };
  
  const columns = [
    {
      title: '目标',
      dataIndex: 'target',
      key: 'target',
    },
    {
      title: '扫描类型',
      dataIndex: 'scan_type',
      key: 'scan_type',
      render: (text: string) => text === 'port' ? '端口扫描' : '漏洞扫描',
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (text: string) => getStatusTag(text),
    },
    {
      title: '开始时间',
      dataIndex: 'start_time',
      key: 'start_time',
      render: (text: string) => formatTime(text),
    },
    {
      title: '结束时间',
      dataIndex: 'end_time',
      key: 'end_time',
      render: (text: string) => text ? formatTime(text) : '-',
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: ScanResult) => (
        <Button 
          type="primary" 
          icon={<EyeOutlined />} 
          size="small"
          onClick={() => onViewResult(record)}
          disabled={record.status !== 'completed'}
        >
          查看
        </Button>
      ),
    },
  ];
  
  return (
    <Card title="扫描历史记录">
      <Table 
        columns={columns} 
        dataSource={scanResults} 
        rowKey="id"
        loading={loading}
        pagination={{ pageSize: 10 }}
        locale={{
          emptyText: <Empty description="暂无扫描记录" />
        }}
      />
    </Card>
  );
};

export default ScanHistory; 