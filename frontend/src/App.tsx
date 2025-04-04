import React, { useState, useEffect } from 'react';
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import { Layout, Typography, Card, Row, Col, Button, Menu, Input, Table, Tag, message, Radio, Empty } from 'antd';
import axios from 'axios';

const { Header, Content, Sider } = Layout;
const { Title, Paragraph } = Typography;
const { Column } = Table;

// 定义扫描结果类型
interface ScanResult {
  id: string;
  scan_id: string;
  target: string;
  scan_type: string;
  start_time: string;
  end_time?: string;
  status: string;
  summary: string;
  vulnerabilities?: Array<{
    name: string;
    severity: string;
    description: string;
    recommendation: string;
  }>;
  open_ports?: Array<{
    port: number;
    service: string;
    state: string;
    version?: string;
  }>;
  risk_score?: number;
}

// 简单的首页组件
const HomePage = () => {
  const navigate = useNavigate();
  
  return (
    <div style={{ padding: 24 }}>
      <Typography>
        <Title level={2}>安全扫描系统</Title>
        <Paragraph>
          欢迎使用安全扫描系统，本系统提供专业的端口扫描和漏洞扫描功能，帮助您发现潜在的安全风险。
        </Paragraph>
      </Typography>
      
      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col span={8}>
          <Card title="端口扫描" hoverable>
            <p>检测目标系统开放的网络端口，识别运行的服务和版本信息</p>
            <Button type="primary" onClick={() => navigate('/security')}>
              开始扫描
            </Button>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="漏洞扫描" hoverable>
            <p>检测目标系统的安全漏洞，提供详细的漏洞信息和修复建议</p>
            <Button type="primary" onClick={() => navigate('/security')}>
              开始扫描
            </Button>
          </Card>
        </Col>
        <Col span={8}>
          <Card title="扫描历史" hoverable>
            <p>查看历史扫描记录和详细报告</p>
            <Button onClick={() => navigate('/security')}>查看历史</Button>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

// 安全扫描页面
const SecurityPage = () => {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('port');
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<any[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  
  // 获取扫描历史
  const fetchScanHistory = async () => {
    try {
      setLoading(true);
      
      try {
        const response = await axios.get('/api/security/results');
        console.log('获取到的扫描历史:', response.data);
        setScanHistory(response.data || []);
      } catch (error) {
        console.error('获取扫描历史失败:', error);
        setScanHistory([]);
        
        if (process.env.NODE_ENV === 'development') {
          console.error('获取扫描历史失败:', error);
        }
      }
    } finally {
      setLoading(false);
    }
  };
  
  useEffect(() => {
    fetchScanHistory();
  }, []);
  
  // 开始扫描
  const handleScan = async () => {
    if (!target) {
      message.error('请输入目标');
      return;
    }
    
    setScanning(true);
    setScanResults([]);
    
    try {
      // 发送扫描请求
      const response = await axios.post('/api/security/scan', {
        target,
        scan_type: scanType
      });
      
      console.log('扫描响应:', response.data);
      
      // 获取扫描ID
      const scanId = response.data.scan_id;
      
      if (scanId) {
        // 等待扫描完成并获取结果
        await waitForScanCompletion(scanId);
      } else {
        message.error('扫描启动失败，未返回扫描ID');
        setScanning(false);
      }
    } catch (error) {
      console.error('扫描错误:', error);
      message.error('扫描请求失败');
      setScanning(false);
    }
  };
  
  // 等待扫描完成并获取结果
  const waitForScanCompletion = async (scanId: string) => {
    console.log('开始等待扫描完成，ID:', scanId);
    
    const maxRetries = 30;
    const retryInterval = 2000; // 2秒
    let retries = 0;
    
    while (retries < maxRetries) {
      try {
        // 尝试获取扫描结果
        const resultResponse = await axios.get(`/api/security/results/${scanId}`);
        
        if (resultResponse.status === 200 && resultResponse.data) {
          // 扫描完成，处理结果
          const scanResult = resultResponse.data;
          
          if (scanResult.status === 'completed' || scanResult.status === 'failed') {
            console.log('扫描完成:', scanResult);
            
            // 处理扫描结果
            if (scanResult.results) {
              setScanResults(scanResult.results);
            }
            
            // 刷新扫描历史
            fetchScanHistory();
            
            setScanning(false);
            return;
          }
        }
      } catch (error) {
        console.error('检查扫描状态失败:', error);
        
        // 如果是404错误，可能扫描还未完成，继续等待
        if (axios.isAxiosError(error) && error.response?.status !== 404) {
          console.error('获取扫描结果失败:', error);
          setScanning(false);
          return;
        }
      }
      
      // 等待后再次尝试
      await new Promise(resolve => setTimeout(resolve, retryInterval));
      retries++;
    }
    
    message.error('扫描超时，请稍后查看结果');
    setScanning(false);
  };
  
  // 查看扫描结果
  const viewScanResult = async (record: ScanResult) => {
    try {
      const response = await axios.get(`/api/security/results/${record.scan_id}`);
      console.log('扫描结果:', response.data);
      
      // 设置选中的扫描结果，用于显示详情
      setSelectedScan(response.data);
      
      // 如果有结果，显示结果
      if (response.data.results) {
        setScanResults(response.data.results);
        setScanType(response.data.scan_type); // 设置扫描类型，以便正确显示结果
      }
    } catch (error) {
      console.error('获取扫描结果失败:', error);
      message.error('获取扫描结果失败');
    }
  };
  
  // 格式化日期时间
  const formatDateTime = (dateTimeStr: string | null) => {
    if (!dateTimeStr) return '未知';
    try {
      const date = new Date(dateTimeStr);
      if (isNaN(date.getTime())) return '无效日期';
      return date.toLocaleString('zh-CN');
    } catch (error) {
      return '无效日期';
    }
  };
  
  // 表格列定义
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
      render: (status: string) => {
        let color = 'default';
        let text = '未知';
        
        switch (status) {
          case 'completed':
            color = 'success';
            text = '已完成';
            break;
          case 'running':
            color = 'processing';
            text = '进行中';
            break;
          case 'failed':
            color = 'error';
            text = '失败';
            break;
        }
        
        return <Tag color={color}>{text}</Tag>;
      },
    },
    {
      title: '开始时间',
      dataIndex: 'start_time',
      key: 'start_time',
      render: (text: string) => formatDateTime(text),
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: ScanResult) => (
        <Button 
          type="primary" 
          size="small" 
          onClick={() => viewScanResult(record)}
          disabled={record.status !== 'completed'}
        >
          查看
        </Button>
      ),
    },
  ];
  
  // 渲染扫描结果
  const renderScanResults = () => {
    if (!scanResults || scanResults.length === 0) {
      return <Empty description="暂无扫描结果" />;
    }

    if (scanType === 'port') {
      const portColumns = [
        { title: "端口", dataIndex: "port", key: "port" },
        { title: "状态", dataIndex: "status", key: "status" },
        { title: "服务", dataIndex: "service", key: "service" }
      ];
      
      return (
        <Table 
          dataSource={scanResults} 
          columns={portColumns}
          rowKey={(record, index = 0) => index.toString()} 
        />
      );
    } else {
      const vulnColumns = [
        { title: "漏洞名称", dataIndex: "name", key: "name" },
        { title: "严重程度", dataIndex: "severity", key: "severity" },
        { title: "描述", dataIndex: "description", key: "description" },
        { title: "修复建议", dataIndex: "recommendation", key: "recommendation" }
      ];
      
      return (
        <Table 
          dataSource={scanResults} 
          columns={vulnColumns}
          rowKey={(record, index = 0) => index.toString()} 
        />
      );
    }
  };
  
  return (
    <div style={{ padding: 24 }}>
      <Title level={2}>安全扫描</Title>
      
      <Card title="开始新的扫描" style={{ marginBottom: 24 }}>
        <div style={{ marginBottom: 16 }}>
          <Radio.Group 
            value={scanType} 
            onChange={(e) => setScanType(e.target.value)}
            style={{ marginBottom: 16 }}
          >
            <Radio.Button value="port">端口扫描</Radio.Button>
            <Radio.Button value="vulnerability">漏洞扫描</Radio.Button>
          </Radio.Group>
        </div>
        
        <div style={{ display: 'flex', gap: 16 }}>
          <Input 
            placeholder="输入目标域名或IP" 
            value={target} 
            onChange={(e) => setTarget(e.target.value)} 
            style={{ width: 300 }}
          />
          <Button 
            type="primary" 
            onClick={handleScan} 
            loading={scanning}
          >
            开始扫描
          </Button>
        </div>
      </Card>
      
      {/* 显示选中的扫描结果 */}
      {selectedScan && (
        <Card 
          title={`扫描结果: ${selectedScan.target} (${selectedScan.scan_type === 'port' ? '端口扫描' : '漏洞扫描'})`}
          style={{ marginBottom: 24 }}
          extra={<Button size="small" onClick={() => setSelectedScan(null)}>关闭</Button>}
        >
          <div style={{ marginBottom: 16 }}>
            <p><strong>扫描ID:</strong> {selectedScan.scan_id}</p>
            <p><strong>开始时间:</strong> {formatDateTime(selectedScan.start_time)}</p>
            <p><strong>结束时间:</strong> {formatDateTime(selectedScan.end_time)}</p>
            <p><strong>状态:</strong> {selectedScan.status === 'completed' ? '已完成' : selectedScan.status === 'failed' ? '失败' : '进行中'}</p>
          </div>
          
          {renderScanResults()}
        </Card>
      )}
      
      <Card title="扫描历史">
        <Table 
          columns={columns} 
          dataSource={scanHistory} 
          rowKey="scan_id"
          loading={loading}
        />
      </Card>
    </div>
  );
};

// 应用布局和路由
const App: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  
  const menuItems = [
    {
      key: '/',
      label: '首页'
    },
    {
      key: '/security',
      label: '安全扫描'
    }
  ];
  
  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center' }}>
        <div style={{ color: 'white', fontSize: 20, fontWeight: 'bold' }}>
          安全扫描系统
        </div>
      </Header>
      <Layout>
        <Sider width={200} style={{ background: '#fff' }}>
          <Menu
            mode="inline"
            selectedKeys={[location.pathname]}
            style={{ height: '100%', borderRight: 0 }}
            items={menuItems}
            onClick={({ key }) => navigate(key)}
          />
        </Sider>
        <Content style={{ background: '#fff', margin: '24px', padding: '24px', minHeight: 280 }}>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/security" element={<SecurityPage />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  );
};

export default App; 