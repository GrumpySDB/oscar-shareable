import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
    build: {
        rollupOptions: {
            input: {
                main: resolve(__dirname, 'index.html'),
                admin: resolve(__dirname, 'admin.html'),
                invite: resolve(__dirname, 'invite.html'),
                faq: resolve(__dirname, 'faq.html'),
                howto: resolve(__dirname, 'how-to-uploader.html'),
                privacy: resolve(__dirname, 'privacy-security-policy.html'),
            },
        },
        outDir: 'dist',
        emptyOutDir: true,
    },
});
