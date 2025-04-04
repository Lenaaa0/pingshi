import React from 'react';
import { 
  Modal, 
  Typography, 
  Table, 
  Card, 
  Tag, 
  Button
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