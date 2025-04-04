import axios from 'axios';
import { ScanRequest, ScanResult } from '../models/types';

const API_BASE_URL = '/api/security';

export const securityApi = {
  // 获取扫描历史
  getScanHistory: async (): Promise<ScanResult[]> => {
    const response = await axios.get(`${API_BASE_URL}/history`);
    return response.data;
  },

  // 获取扫描结果
  getScanResult: async (id: string): Promise<ScanResult> => {
    const response = await axios.get(`${API_BASE_URL}/result/${id}`);
    return response.data;
  },

  // 开始端口扫描
  startPortScan: async (data: ScanRequest): Promise<{ id: string }> => {
    const response = await axios.post(`${API_BASE_URL}/scan/port`, data);
    return response.data;
  },

  // 开始漏洞扫描
  startVulnerabilityScan: async (data: ScanRequest): Promise<{ id: string }> => {
    const response = await axios.post(`${API_BASE_URL}/scan`, data);
    return response.data;
  },

  // 等待扫描完成
  waitForScanCompletion: async (scanId: string, maxAttempts = 30): Promise<ScanResult> => {
    let attempts = 0;
    
    while (attempts < maxAttempts) {
      const result = await securityApi.getScanResult(scanId);
      if (result.status !== 'running') {
        return result;
      }
      
      // 等待2秒再检查
      await new Promise(resolve => setTimeout(resolve, 2000));
      attempts++;
    }
    
    throw new Error('Scan timeout');
  }
}; 