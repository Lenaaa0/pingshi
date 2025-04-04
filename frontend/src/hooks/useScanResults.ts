import { useState, useEffect } from 'react';
import { securityApi } from '../api/securityApi';
import { ScanResult } from '../models/types';

export const useScanResults = () => {
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchScanResults = async () => {
    try {
      setLoading(true);
      const results = await securityApi.getScanHistory();
      setScanResults(results);
      setError(null);
    } catch (err) {
      console.error('Failed to fetch scan results:', err);
      setError(err instanceof Error ? err : new Error('Unknown error'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanResults();
  }, []);

  return {
    scanResults,
    currentResult,
    setCurrentResult,
    loading,
    error,
    fetchScanResults
  };
}; 