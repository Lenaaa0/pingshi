import React, { useState } from 'react';
import { 
  Card, 
  Table, 
  Tag, 
  Typography, 
  Tabs,
  Statistic,
  Row,
  Col,
  Divider,
  Progress,
  List,
  Badge,
  Alert,
  Space
} from 'antd';
import { ScanResult, VulnerabilityDetail, PortDetail } from '../../models/types';
import {
  ExclamationCircleOutlined,
  CheckCircleOutlined,
  InfoCircleOutlined,
  WarningOutlined,
  BugOutlined,
  SecurityScanOutlined,
  DatabaseOutlined,
  GlobalOutlined
} from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;
const { TabPane } = Tabs;

interface ScanResultDetailProps {
  result: ScanResult;
}

const ScanResultDetail: React.FC<ScanResultDetailProps> = ({ result }) => {
  const [activeTab, setActiveTab] = useState('overview');
  
  // 计算不同严重级别的漏洞数量
  const getVulnCountBySeverity = (severity: string) => {
    if (!result.vulnerabilities) return 0;
    return result.vulnerabilities.filter(v => 
      v.severity.toLowerCase() === severity.toLowerCase()
    ).length;
  };
  
  const criticalCount = getVulnCountBySeverity('critical');
  const highCount = getVulnCountBySeverity('high');
  const mediumCount = getVulnCountBySeverity('medium');
  const lowCount = getVulnCountBySeverity('low');
  const infoCount = getVulnCountBySeverity('info');
  
  const totalVulns = (result.vulnerabilities?.length || 0);
  const totalPorts = (result.open_ports?.length || 0);
  
  // 获取漏洞严重程度的颜色和图标
  const getSeverityInfo = (severity: string) => {
    const severityLower = severity.toLowerCase();
    switch(severityLower) {
      case 'critical':
        return { color: '#a50000', icon: <ExclamationCircleOutlined />, text: '严重' };
      case 'high':
        return { color: '#ff4d4f', icon: <ExclamationCircleOutlined />, text: '高危' };
      case 'medium':
        return { color: '#faad14', icon: <WarningOutlined />, text: '中危' };
      case 'low':
        return { color: '#1890ff', icon: <InfoCircleOutlined />, text: '低危' };
      default:
        return { color: '#52c41a', icon: <CheckCircleOutlined />, text: '信息' };
    }
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
      render: (severity: string) => {
        const { color, icon, text } = getSeverityInfo(severity);
        return (
          <Tag color={color} icon={icon}>
            {text}
          </Tag>
        );
      },
      filters: [
        { text: '严重', value: 'critical' },
        { text: '高危', value: 'high' },
        { text: '中危', value: 'medium' },
        { text: '低危', value: 'low' },
        { text: '信息', value: 'info' }
      ],
      onFilter: (value: any, record: VulnerabilityDetail) => 
        record.severity.toLowerCase() === value.toString().toLowerCase(),
      sorter: (a: VulnerabilityDetail, b: VulnerabilityDetail) => {
        const severityOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        const aSeverity = a.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info';
        const bSeverity = b.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info';
        return severityOrder[aSeverity] - severityOrder[bSeverity];
      },
      defaultSortOrder: 'descend' as const,
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      width: '40%',
      ellipsis: true,
    },
    {
      title: '修复建议',
      dataIndex: 'recommendation',
      key: 'recommendation',
      width: '30%',
      ellipsis: true,
    }
  ];
  
  // 端口表格列定义
  const portColumns = [
    {
      title: '端口',
      dataIndex: 'port',
      key: 'port',
      sorter: (a: PortDetail, b: PortDetail) => a.port - b.port,
    },
    {
      title: '服务',
      dataIndex: 'service',
      key: 'service',
      filters: [
        { text: 'HTTP', value: 'http' },
        { text: 'HTTPS', value: 'https' },
        { text: 'SSH', value: 'ssh' },
        { text: 'FTP', value: 'ftp' },
        { text: 'MySQL', value: 'mysql' },
        { text: 'MSSQL', value: 'mssql' },
        { text: 'RDP', value: 'rdp' },
      ],
      onFilter: (value: any, record: PortDetail) => 
        record.service.toLowerCase() === value.toString().toLowerCase(),
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
  
  // 获取风险评级描述
  const getRiskRating = (score: number) => {
    if (score >= 75) return { text: '严重', color: '#a50000' };
    if (score >= 50) return { text: '高风险', color: '#ff4d4f' };
    if (score >= 25) return { text: '中风险', color: '#faad14' };
    return { text: '低风险', color: '#52c41a' };
  };
  
  return (
    <div className="scan-result-detail">
      <Card bordered={false}>
        <Row gutter={16}>
          <Col xs={24} md={16}>
            <Space direction="vertical" style={{ width: '100%' }}>
              <Title level={4}>
                <SecurityScanOutlined /> 扫描目标: {result.target}
              </Title>
              <Paragraph>
                <Space split={<Divider type="vertical" />}>
                  <Text strong>扫描类型:</Text> 
                  <Text>{result.scan_type === 'port' ? '端口扫描' : '漏洞扫描'}</Text>
                  
                  <Text strong>开始时间:</Text> 
                  <Text>{new Date(result.start_time).toLocaleString()}</Text>
                  
                  <Text strong>结束时间:</Text> 
                  <Text>{result.end_time ? new Date(result.end_time).toLocaleString() : '进行中'}</Text>
                </Space>
              </Paragraph>
              <Paragraph>
                <Alert
                  message="扫描结果摘要"
                  description={result.summary}
                  type={highCount > 0 ? "error" : mediumCount > 0 ? "warning" : "success"}
                  showIcon
                />
              </Paragraph>
            </Space>
          </Col>
          <Col xs={24} md={8}>
            {result.risk_score !== undefined && (
              <Card>
                <Statistic 
                  title="风险评分" 
                  value={result.risk_score} 
                  suffix="/ 100"
                  valueStyle={{ 
                    color: result.risk_score > 75 ? '#a50000' :
                           result.risk_score > 50 ? '#ff4d4f' : 
                           result.risk_score > 25 ? '#faad14' : '#52c41a' 
                  }} 
                />
                <Progress 
                  percent={result.risk_score} 
                  status={
                    result.risk_score > 75 ? 'exception' : 
                    result.risk_score > 25 ? 'normal' : 'success'
                  }
                  strokeColor={
                    result.risk_score > 75 ? '#a50000' :
                    result.risk_score > 50 ? '#ff4d4f' : 
                    result.risk_score > 25 ? '#faad14' : '#52c41a'
                  }
                />
                <Text type="secondary">
                  风险等级: <Text style={{ color: getRiskRating(result.risk_score).color }}>
                    {getRiskRating(result.risk_score).text}
                  </Text>
                </Text>
              </Card>
            )}
          </Col>
        </Row>
      </Card>
      
      <Tabs activeKey={activeTab} onChange={setActiveTab} style={{ marginTop: 16 }}>
        <TabPane 
          tab={
            <span>
              <InfoCircleOutlined />
              概览
            </span>
          } 
          key="overview"
        >
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={8}>
              <Card>
                <Statistic 
                  title="发现漏洞" 
                  value={totalVulns} 
                  valueStyle={{ color: totalVulns > 0 ? '#ff4d4f' : '#52c41a' }}
                  prefix={<BugOutlined />}
                />
              </Card>
            </Col>
            <Col xs={24} sm={8}>
              <Card>
                <Statistic 
                  title="开放端口" 
                  value={totalPorts} 
                  valueStyle={{ color: '#1890ff' }}
                  prefix={<DatabaseOutlined />}
                />
              </Card>
            </Col>
            <Col xs={24} sm={8}>
              <Card>
                <Statistic 
                  title="扫描耗时" 
                  value={
                    result.start_time && result.end_time ? 
                    Math.round((new Date(result.end_time).getTime() - new Date(result.start_time).getTime()) / 1000) :
                    0
                  } 
                  suffix="秒"
                  valueStyle={{ color: '#722ed1' }}
                  prefix={<GlobalOutlined />}
                />
              </Card>
            </Col>
          </Row>
          
          <Card title="漏洞严重程度分布" style={{ marginTop: 16 }}>
            <Row gutter={[16, 16]}>
              {criticalCount > 0 && (
                <Col span={4}>
                  <Badge count={criticalCount} style={{ backgroundColor: '#a50000' }}>
                    <Card>
                      <div style={{ textAlign: 'center', color: '#a50000' }}>
                        <ExclamationCircleOutlined style={{ fontSize: 24 }} />
                        <div>严重</div>
                      </div>
                    </Card>
                  </Badge>
                </Col>
              )}
              {highCount > 0 && (
                <Col span={4}>
                  <Badge count={highCount} style={{ backgroundColor: '#ff4d4f' }}>
                    <Card>
                      <div style={{ textAlign: 'center', color: '#ff4d4f' }}>
                        <ExclamationCircleOutlined style={{ fontSize: 24 }} />
                        <div>高危</div>
                      </div>
                    </Card>
                  </Badge>
                </Col>
              )}
              {mediumCount > 0 && (
                <Col span={4}>
                  <Badge count={mediumCount} style={{ backgroundColor: '#faad14' }}>
                    <Card>
                      <div style={{ textAlign: 'center', color: '#faad14' }}>
                        <WarningOutlined style={{ fontSize: 24 }} />
                        <div>中危</div>
                      </div>
                    </Card>
                  </Badge>
                </Col>
              )}
              {lowCount > 0 && (
                <Col span={4}>
                  <Badge count={lowCount} style={{ backgroundColor: '#1890ff' }}>
                    <Card>
                      <div style={{ textAlign: 'center', color: '#1890ff' }}>
                        <InfoCircleOutlined style={{ fontSize: 24 }} />
                        <div>低危</div>
                      </div>
                    </Card>
                  </Badge>
                </Col>
              )}
              {infoCount > 0 && (
                <Col span={4}>
                  <Badge count={infoCount} style={{ backgroundColor: '#52c41a' }}>
                    <Card>
                      <div style={{ textAlign: 'center', color: '#52c41a' }}>
                        <CheckCircleOutlined style={{ fontSize: 24 }} />
                        <div>信息</div>
                      </div>
                    </Card>
                  </Badge>
                </Col>
              )}
              {totalVulns === 0 && (
                <Col span={24}>
                  <Alert
                    message="未发现漏洞"
                    description="在此次扫描中未发现任何安全漏洞。这可能表示您的系统安全配置良好，但仍建议定期进行安全评估。"
                    type="success"
                    showIcon
                  />
                </Col>
              )}
            </Row>
          </Card>
          
          {(criticalCount > 0 || highCount > 0) && (
            <Card title="需要立即修复的漏洞" style={{ marginTop: 16 }}>
              <List
                itemLayout="horizontal"
                dataSource={result.vulnerabilities?.filter(v => 
                  v.severity.toLowerCase() === 'critical' || v.severity.toLowerCase() === 'high'
                ) || []}
                renderItem={item => (
                  <List.Item>
                    <List.Item.Meta
                      avatar={
                        <ExclamationCircleOutlined style={{ 
                          fontSize: 24, 
                          color: item.severity.toLowerCase() === 'critical' ? '#a50000' : '#ff4d4f' 
                        }} />
                      }
                      title={<Text strong>{item.name}</Text>}
                      description={item.description}
                    />
                    <div>
                      <Text type="secondary">建议：</Text>
                      <br />
                      <Text>{item.recommendation}</Text>
                    </div>
                  </List.Item>
                )}
              />
            </Card>
          )}
        </TabPane>
        
        <TabPane 
          tab={
            <span>
              <BugOutlined />
              漏洞详情
              {totalVulns > 0 && <Badge count={totalVulns} style={{ marginLeft: 8 }} />}
            </span>
          } 
          key="vulnerabilities"
        >
          {totalVulns > 0 ? (
            <Table 
              dataSource={result.vulnerabilities} 
              columns={vulnerabilityColumns}
              rowKey="name"
              expandable={{
                expandedRowRender: record => (
                  <div style={{ margin: 0 }}>
                    <Paragraph>
                      <Text strong>详细描述：</Text>
                      <br />
                      {record.description}
                    </Paragraph>
                    <Paragraph>
                      <Text strong>修复建议：</Text>
                      <br />
                      {record.recommendation}
                    </Paragraph>
                  </div>
                ),
              }}
            />
          ) : (
            <Alert
              message="未发现漏洞"
              description="在此次扫描中未发现任何安全漏洞。"
              type="success"
              showIcon
            />
          )}
        </TabPane>
        
        <TabPane 
          tab={
            <span>
              <DatabaseOutlined />
              端口信息
              {totalPorts > 0 && <Badge count={totalPorts} style={{ marginLeft: 8 }} />}
            </span>
          } 
          key="ports"
        >
          {totalPorts > 0 ? (
            <Table 
              dataSource={result.open_ports} 
              columns={portColumns}
              rowKey="port"
            />
          ) : (
            <Alert
              message="未发现开放端口"
              description="在此次扫描中未发现任何开放的端口。"
              type="info"
              showIcon
            />
          )}
        </TabPane>
        
        <TabPane 
          tab={
            <span>
              <SecurityScanOutlined />
              安全建议
            </span>
          } 
          key="recommendations"
        >
          <Card>
            <Title level={4}>安全加固建议</Title>
            
            {result.vulnerabilities && result.vulnerabilities.length > 0 ? (
              <>
                <Paragraph>
                  根据扫描结果，我们为您提供以下安全加固建议，按风险优先级排序：
                </Paragraph>
                
                <List
                  itemLayout="vertical"
                  dataSource={[...result.vulnerabilities].sort((a, b) => {
                    const severityOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
                    const aSeverity = a.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info';
                    const bSeverity = b.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info';
                    return severityOrder[bSeverity] - severityOrder[aSeverity];
                  })}
                  renderItem={(item, index) => (
                    <List.Item>
                      <List.Item.Meta
                        avatar={
                          <div style={{ 
                            background: getSeverityInfo(item.severity).color, 
                            color: 'white', 
                            width: 24, 
                            height: 24, 
                            borderRadius: '50%', 
                            display: 'flex', 
                            justifyContent: 'center', 
                            alignItems: 'center' 
                          }}>
                            {index + 1}
                          </div>
                        }
                        title={
                          <Space>
                            {item.name}
                            <Tag color={getSeverityInfo(item.severity).color}>
                              {getSeverityInfo(item.severity).text}
                            </Tag>
                          </Space>
                        }
                        description={item.recommendation}
                      />
                    </List.Item>
                  )}
                />
              </>
            ) : (
              <Alert
                message="良好的安全状态"
                description="未发现明显的安全漏洞。为了保持良好的安全状态，建议：
                1. 定期更新系统和应用程序
                2. 维持强密码策略
                3. 定期执行安全扫描
                4. 启用防火墙并正确配置
                5. 如有必要，仅开放必需的端口"
                type="success"
                showIcon
              />
            )}
          </Card>
        </TabPane>
      </Tabs>
    </div>
  );
};

export default ScanResultDetail; 