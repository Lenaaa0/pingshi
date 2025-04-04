import React, { useState, useEffect } from 'react';
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import { Layout, Typography, Card, Row, Col, Button, Menu, Input, Table, Tag, message, Radio } from 'antd';
import axios from 'axios';

const { Header, Content, Sider } = Layout;
const { Title, Paragraph } = Typography;

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
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);
  
  // 获取扫描历史
  const fetchScanHistory = async () => {
    try {
      setLoading(true);
      
      try {
        const response = await axios.get('/api/security/results');
        setScanResults(response.data || []);
      } catch (error) {
        console.error('获取扫描历史失败:', error);
        setScanResults([]);
        
        if (process.env.NODE_ENV === 'development') {
          message.error('获取扫描历史失败');
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
      
      // 确保我们从响应中获取scan_id
      const scanId = response.data.scan_id;
      
      if (!scanId) {
        throw new Error('未获取到扫描ID');
      }
      
      // 等待扫描完成并获取结果
      await waitForScanCompletion(scanId);
    } catch (error) {
      console.error('扫描失败:', error);
      message.error('扫描失败');
    } finally {
      setScanning(false);
    }
  };
  
  // 等待扫描完成
  const waitForScanCompletion = async (scanId: string) => {
    console.log('开始等待扫描完成，ID:', scanId);
    
    let retries = 0;
    const maxRetries = 30; // 最多尝试30次
    const retryInterval = 2000; // 每2秒尝试一次
    
    while (retries < maxRetries) {
      try {
        // 尝试获取扫描结果
        const resultResponse = await axios.get(`/api/security/scan/${scanId}/results`);
        
        if (resultResponse.data && resultResponse.data.status === 'completed') {
          // 扫描完成，获取结果
          setScanResults(resultResponse.data.results || []);
          message.success('扫描完成');
          return;
        } else if (resultResponse.data && resultResponse.data.status === 'failed') {
          throw new Error('扫描失败');
        }
        
        // 如果扫描仍在进行中，等待后再次尝试
        await new Promise(resolve => setTimeout(resolve, retryInterval));
        retries++;
      } catch (error) {
        console.error('检查扫描状态失败:', error);
        
        // 尝试备用路径
        try {
          const statusResponse = await axios.get(`/api/security/scan/${scanId}`);
          
          if (statusResponse.data && statusResponse.data.status === 'completed') {
            // 扫描完成，获取结果
            setScanResults(statusResponse.data.results || []);
            message.success('扫描完成');
            return;
          } else if (statusResponse.data && statusResponse.data.status === 'failed') {
            throw new Error('扫描失败');
          }
        } catch (statusError) {
          console.error('备用路径也失败:', statusError);
        }
        
        // 等待后再次尝试
        await new Promise(resolve => setTimeout(resolve, retryInterval));
        retries++;
      }
    }
    
    message.error('扫描超时，请稍后查看结果');
  };
  
  // 查看扫描结果
  const viewScanResult = async (id: string) => {
    try {
      // 尝试不同的API路径
      let response;
      try {
        response = await axios.get(`/api/security/results/${id}`);
      } catch (error) {
        if (axios.isAxiosError(error) && error.response?.status === 404) {
          // 如果第一个路径返回404，尝试第二个路径
          response = await axios.get(`/api/security/scan/${id}`);
        } else {
          throw error;
        }
      }
      
      console.log('扫描结果:', response.data);
      message.info('请在控制台查看扫描结果');
    } catch (error) {
      console.error('获取扫描结果失败:', error);
      message.error('获取扫描结果失败');
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
      render: (text: string) => new Date(text).toLocaleString(),
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: ScanResult) => (
        <Button 
          type="primary" 
          size="small" 
          onClick={() => viewScanResult(record.id)}
          disabled={record.status !== 'completed'}
        >
          查看
        </Button>
      ),
    },
  ];
  
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
      
      <Card title="扫描历史">
        <Table 
          columns={columns} 
          dataSource={scanResults || []}
          rowKey="id"
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