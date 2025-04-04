import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // 将 /api 开头的请求代理到后端服务器
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        // 不要重写路径
        // rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
