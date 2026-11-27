/// <reference types="vitest/config" />
import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const here = import.meta.dirname

export default defineConfig({
  // The page is served at https://<host>/<token>/ so every asset URL must be relative.
  base: './',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(here, './src') },
  },
  build: {
    outDir: path.resolve(here, '../secure_input/static'),
    emptyOutDir: true,
    // CSP is script-src 'self': no inline polyfill script, no data: URL assets.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
})
