import React from 'react';
import { Typography, Card, Row, Col, Button, Statistic } from 'antd';
import { 
  SafetyCertificateOutlined, 
  ScanOutlined, 
  BugOutlined,
  ArrowRightOutlined
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';

const { Title, Paragraph } = Typography;

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  
  return (
    <div>
      <Typography>
        <Title level={2}>安全扫描系统</Title>
        <Paragraph>
          欢迎使用安全扫描系统，本系统提供专业的端口扫描和漏洞扫描功能，帮助您发现潜在的安全风险。
        </Paragraph>
      </Typography>
      
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} sm={8}>
          <Card 
            hoverable
            style={{ height: '100%' }}
            cover={
              <div style={{ 
                background: 'linear-gradient(120deg, #1890ff, #096dd9)', 
                height: 120, 
                display: 'flex', 
                justifyContent: 'center', 
                alignItems: 'center' 
              }}>
                <SafetyCertificateOutlined style={{ fontSize: 48, color: 'white' }} />
              </div>
            }
            actions={[
              <Button 
                type="link" 
                onClick={() => navigate('/security')}
                icon={<ArrowRightOutlined />}
              >
                开始扫描
              </Button>
            ]}
          >
            <Card.Meta
              title="安全扫描"
              description="全面检测目标系统的安全漏洞和开放端口，提供专业的安全评估报告"
            />
          </Card>
        </Col>
        
        <Col xs={24} sm={8}>
          <Card 
            hoverable
            style={{ height: '100%' }}
            cover={
              <div style={{ 
                background: 'linear-gradient(120deg, #52c41a, #389e0d)', 
                height: 120, 
                display: 'flex', 
                justifyContent: 'center', 
                alignItems: 'center' 
              }}>
                <ScanOutlined style={{ fontSize: 48, color: 'white' }} />
              </div>
            }
            actions={[
              <Button 
                type="link" 
                onClick={() => navigate('/security')}
                icon={<ArrowRightOutlined />}
              >
                了解更多
              </Button>
            ]}
          >
            <Card.Meta
              title="端口扫描"
              description="检测目标系统开放的网络端口，识别运行的服务和版本信息"
            />
          </Card>
        </Col>
        
        <Col xs={24} sm={8}>
          <Card 
            hoverable
            style={{ height: '100%' }}
            cover={
              <div style={{ 
                background: 'linear-gradient(120deg, #fa8c16, #d46b08)', 
                height: 120, 
                display: 'flex', 
                justifyContent: 'center', 
                alignItems: 'center' 
              }}>
                <BugOutlined style={{ fontSize: 48, color: 'white' }} />
              </div>
            }
            actions={[
              <Button 
                type="link" 
                onClick={() => navigate('/security')}
                icon={<ArrowRightOutlined />}
              >
                了解更多
              </Button>
            ]}
          >
            <Card.Meta
              title="漏洞扫描"
              description="检测目标系统的安全漏洞，提供详细的漏洞信息和修复建议"
            />
          </Card>
        </Col>
      </Row>
      
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic
              title="安全评分"
              value={85}
              suffix="/ 100"
              valueStyle={{ color: '#3f8600' }}
              prefix={<SafetyCertificateOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic
              title="已完成扫描"
              value={12}
              valueStyle={{ color: '#1890ff' }}
              prefix={<ScanOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card>
            <Statistic
              title="发现漏洞"
              value={3}
              valueStyle={{ color: '#cf1322' }}
              prefix={<BugOutlined />}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard; 