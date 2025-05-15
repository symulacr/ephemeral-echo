import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    esbuildOptions: { 
      target: "esnext" // gotta use js for top-lvl await w/ bb.js
    },
    // keep these libs out cuz they load wasm their own way
    // noir stuff handles itself idk
    exclude: ['@noir-lang/noirc_abi', '@noir-lang/acvm_js'] 
  },
  build: { 
    target: "esnext" // need modern output too ......
  },
  // might need this for wasm mime type probs
  // server: {
  //   mimeTypes: {
  //     '.wasm': 'application/wasm'
  //   }
  // }
})
