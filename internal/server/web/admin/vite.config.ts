import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: path.resolve(__dirname, '../dist/admin'),
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          const normalized = id.split(path.sep).join('/');

          if (normalized.includes('/src/pages/')) {
            const pageName = path.basename(normalized, path.extname(normalized)).toLowerCase();
            return `page-${pageName}`;
          }

          if (normalized.includes('node_modules')) {
            if (normalized.includes('lucide-react')) {
              return 'vendor-icons';
            }
            if (
              normalized.includes('@dnd-kit/') ||
              normalized.includes('@base-ui/react') ||
              normalized.includes('sonner')
            ) {
              return 'vendor-ui';
            }
            return 'vendor';
          }

          return undefined;
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
  server: {
    // Keep HMR switchable in local automation runs to avoid UI flicker during repeated edits.
    hmr: process.env.DISABLE_HMR !== 'true',
  },
});
