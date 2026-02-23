import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 12000,
    proxy: {
      '/api': {
        target: process.env.VITE_API_ORIGIN || 'http://localhost:12001',
        changeOrigin: true,
      },
    },
  },
});
