/**
 * 格式化时间字符串为本地日期时间格式
 */
export const formatTime = (timeString?: string): string => {
  if (!timeString) return '-';
  try {
    const date = new Date(timeString);
    return date.toLocaleString();
  } catch (error) {
    console.error('时间格式化错误:', error);
    return timeString;
  }
}; 