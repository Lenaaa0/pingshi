export interface VulnerabilityDetail {
  name: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  recommendation: string;
}

export interface PortDetail {
  port: number;
  service: string;
  state: string;
  version?: string;
}

export interface ScanResult {
  id: string;
  scan_id: string;
  target: string;
  scan_type: 'port' | 'vulnerability';
  start_time: string;
  end_time?: string;
  status: 'running' | 'completed' | 'failed';
  summary: string;
  vulnerabilities?: VulnerabilityDetail[];
  open_ports?: PortDetail[];
  risk_score?: number;
}

export interface ScanRequest {
  target: string;
} 