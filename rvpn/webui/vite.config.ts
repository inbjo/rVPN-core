import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  build: {
    outDir: '../crates/rvpn-client/ui-dist',
    emptyOutDir: true,
    assetsInlineLimit: 10000000,
  },
  server: {
    proxy: {
      '/ws': {
        target: 'ws://127.0.0.1:9800',
        ws: true,
        changeOrigin: true,
        rewriteWsOrigin: true,
      },
    },
  },
})
