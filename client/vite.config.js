// ~/ephemeral-echo/client/vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    esbuildOptions: { 
      target: "esnext" // For top-level await in bb.js and other modern JS
    },
    // Exclude these as per the NoirJS tutorial for older versions,
    // to prevent Vite from trying to process them incorrectly.
    // The libraries themselves will handle loading their WASM.
    exclude: ['@noir-lang/noirc_abi', '@noir-lang/acvm_js'] 
  },
  build: { 
    target: "esnext" // Ensure build output is also modern
  },
  // Optional: Attempt to force correct MIME type for WASM if warning persists
  // This might not be necessary if files are correctly found.
  // server: {
  //   mimeTypes: {
  //     '.wasm': 'application/wasm'
  //   }
  // }
})
