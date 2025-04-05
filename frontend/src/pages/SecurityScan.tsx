import React, { useState, useEffect } from 'react';
import { Typography, Tabs, message, Card, Button, Modal, Spin } from 'antd';
import { ScanOutlined, BugOutlined, HistoryOutlined, ReloadOutlined } from '@ant-design/icons';
import PortScanForm from '../components/security/PortScanForm';
import VulnScanForm from '../components/security/VulnScanForm';
import ScanHistory from '../components/security/ScanHistory';
import ScanResultDetail from '../components/security/ScanResultDetail';
import { securityApi } from '../api/securityApi';
import { useScanResults } from '../hooks/useScanResults';
import { ScanResult } from '../models/types';

const { Title } = Typography;
const { TabPane } = Tabs;

const SecurityScan: React.FC = () => {
  const [activeTab, setActiveTab] = useState('port');
  const [scanning, setScanning] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const { 
    scanResults, 
    loading, 
    fetchScanResults, 
    currentResult,
    setCurrentResult 
  } = useScanResults();
  
  useEffect(() => {
    // 初始加载
    fetchScanResults();
  }, [fetchScanResults]);

  const handlePortScan = async (target: string) => {
    if (!target) {
      message.warning('请输入目标域名或IP');
      return;
    }
    
    setScanning(true);
    try {
      message.loading({ content: '正在启动端口扫描...', key: 'scanStatus', duration: 0 });
      
      const { scan_id } = await securityApi.startPortScan({ target });
      message.loading({ content: '端口扫描中，请耐心等待...', key: 'scanStatus', duration: 0 });
      
      // 轮询扫描结果，直到完成
      const result = await pollScanStatus(scan_id);
      
      if (result) {
        message.success({ content: '端口扫描完成！', key: 'scanStatus' });
        // 刷新扫描历史
        fetchScanResults();
        
        // 显示结果
        setCurrentResult(result);
        setModalVisible(true);
      } else {
        message.error({ content: '扫描结果获取失败，请查看历史记录', key: 'scanStatus' });
      }
    } catch (error) {
      console.error('扫描错误:', error);
      message.error({ content: '扫描失败，请稍后再试', key: 'scanStatus' });
    } finally {
      setScanning(false);
    }
  };
  
  const handleVulnScan = async (target: string) => {
    if (!target) {
      message.warning('请输入目标域名或IP');
      return;
    }
    
    setScanning(true);
    try {
      message.loading({ content: '正在启动漏洞扫描...', key: 'scanStatus', duration: 0 });
      
      const { scan_id } = await securityApi.startVulnerabilityScan({ target });
      message.loading({ content: '漏洞扫描中，请耐心等待...', key: 'scanStatus', duration: 0 });
      
      // 轮询扫描结果，直到完成
      const result = await pollScanStatus(scan_id);
      
      if (result) {
        message.success({ content: '漏洞扫描完成！', key: 'scanStatus' });
        // 刷新扫描历史
        fetchScanResults();
        
        // 显示结果
        setCurrentResult(result);
        setModalVisible(true);
      } else {
        message.error({ content: '扫描结果获取失败，请查看历史记录', key: 'scanStatus' });
      }
    } catch (error) {
      console.error('扫描错误:', error);
      message.error({ content: '扫描失败，请稍后再试', key: 'scanStatus' });
    } finally {
      setScanning(false);
    }
  };
  
  // 轮询扫描状态
  const pollScanStatus = async (scanId: string): Promise<ScanResult | null> => {
    const maxAttempts = 120; // 最多等待120次，每次3秒
    let attempts = 0;
    
    while (attempts < maxAttempts) {
      try {
        // 获取扫描状态
        const response = await securityApi.getScanStatus(scanId);
        console.log('Scan status:', response);
        
        if (response.status === 'completed') {
          // 扫描完成，获取详细结果
          const result = await securityApi.getScanResult(scanId);
          return result;
        } else if (response.status === 'failed') {
          message.error('扫描失败');
          return null;
        }
        
        // 如果还在扫描中，等待3秒后再查询
        await new Promise(resolve => setTimeout(resolve, 3000));
        attempts++;
      } catch (error) {
        console.error('查询扫描状态出错:', error);
        return null;
      }
    }
    
    message.warning('扫描超时，请稍后在历史记录中查看结果');
    return null;
  };
  
  const handleViewResult = async (result: ScanResult) => {
    setCurrentResult(result);
    setModalVisible(true);
  };
  
  const handleCloseModal = () => {
    setModalVisible(false);
  };
  
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2}>安全扫描</Title>
        
        <Button 
          type="primary" 
          icon={<ReloadOutlined />} 
          onClick={fetchScanResults}
          loading={loading}
        >
          刷新历史
        </Button>
      </div>
      
      <Tabs 
        activeKey={activeTab} 
        onChange={setActiveTab} 
        type="card"
        size="large"
      >
        <TabPane 
          tab={
            <span>
              <ScanOutlined />
              端口扫描
            </span>
          } 
          key="port"
        >
          <PortScanForm onScan={handlePortScan} scanning={scanning} />
        </TabPane>
        
        <TabPane 
          tab={
            <span>
              <BugOutlined />
              漏洞扫描
            </span>
          } 
          key="vulnerability"
        >
          <VulnScanForm onScan={handleVulnScan} scanning={scanning} />
        </TabPane>
        
        <TabPane 
          tab={
            <span>
              <HistoryOutlined />
              扫描历史
            </span>
          } 
          key="history"
        >
          <ScanHistory 
            scanResults={scanResults} 
            loading={loading} 
            onViewResult={handleViewResult} 
          />
        </TabPane>
      </Tabs>
      
      {/* 扫描结果详情模态框 */}
      <Modal
        title="扫描结果详情"
        open={modalVisible}
        onCancel={handleCloseModal}
        width={1000}
        footer={[
          <Button key="close" onClick={handleCloseModal}>
            关闭
          </Button>,
          <Button key="download" type="primary">
            下载报告
          </Button>
        ]}
        bodyStyle={{ maxHeight: '80vh', overflow: 'auto' }}
      >
        {currentResult ? (
          <ScanResultDetail result={currentResult} />
        ) : (
          <div style={{ textAlign: 'center', padding: '30px 0' }}>
            <Spin tip="加载扫描结果..." />
          </div>
        )}
      </Modal>
    </div>
  );
};

export default SecurityScan; 