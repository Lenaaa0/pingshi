import React, { useState } from 'react';
import { Typography, Tabs, message } from 'antd';
import { ScanOutlined, BugOutlined, HistoryOutlined } from '@ant-design/icons';
import PortScanForm from '../components/security/PortScanForm';
import VulnScanForm from '../components/security/VulnScanForm';
import ScanHistory from '../components/security/ScanHistory';
import { securityApi } from '../api/securityApi';
import { useScanResults } from '../hooks/useScanResults';
import { ScanResult } from '../models/types';

const { Title } = Typography;

const SecurityScan: React.FC = () => {
  const [activeTab, setActiveTab] = useState('port');
  const [scanning, setScanning] = useState(false);
  const { scanResults, loading, fetchScanResults, setCurrentResult } = useScanResults();
  
  const handlePortScan = async (target: string) => {
    if (!target) {
      message.warning('请输入目标域名或IP');
      return;
    }
    
    setScanning(true);
    try {
      const { id } = await securityApi.startPortScan({ target });
      message.success('端口扫描已开始');
      
      // 等待扫描完成
      await securityApi.waitForScanCompletion(id);
      
      // 刷新扫描历史
      fetchScanResults();
      message.success('端口扫描已完成');
    } catch (error) {
      console.error('扫描错误:', error);
      message.error('扫描失败，请稍后再试');
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
      const { id } = await securityApi.startVulnerabilityScan({ target });
      message.success('漏洞扫描已开始');
      
      // 等待扫描完成
      await securityApi.waitForScanCompletion(id);
      
      // 刷新扫描历史
      fetchScanResults();
      message.success('漏洞扫描已完成');
    } catch (error) {
      console.error('扫描错误:', error);
      message.error('扫描失败，请稍后再试');
    } finally {
      setScanning(false);
    }
  };
  
  const handleViewResult = async (result: ScanResult) => {
    setCurrentResult(result);
  };
  
  const items = [
    {
      key: 'port',
      label: (
        <span>
          <ScanOutlined />
          端口扫描
        </span>
      ),
      children: <PortScanForm onScan={handlePortScan} scanning={scanning} />,
    },
    {
      key: 'vulnerability',
      label: (
        <span>
          <BugOutlined />
          漏洞扫描
        </span>
      ),
      children: <VulnScanForm onScan={handleVulnScan} scanning={scanning} />,
    },
    {
      key: 'history',
      label: (
        <span>
          <HistoryOutlined />
          扫描历史
        </span>
      ),
      children: (
        <ScanHistory 
          scanResults={scanResults} 
          loading={loading} 
          onViewResult={handleViewResult} 
        />
      ),
    },
  ];
  
  return (
    <div>
      <Title level={2}>安全扫描</Title>
      
      <Tabs 
        activeKey={activeTab} 
        onChange={setActiveTab} 
        items={items}
        type="card"
        size="large"
        style={{ marginTop: 24 }}
      />
    </div>
  );
};

export default SecurityScan; 