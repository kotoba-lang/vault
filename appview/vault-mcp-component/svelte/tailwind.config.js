import plugin from 'tailwindcss/plugin';
import { etzhayyimUIKit } from '@etzhayyim/design-system/plugin';

export default {
  content: [
    './src/**/*.{html,js,svelte,ts}',
    '../../../../../packages/ts/design-system/dist/**/*.{svelte,js}',
    '../../../../../packages/ts/design-system/dist/**/*.{svelte,js}',
    '../../../../../packages/ts/appshellv2/src/**/*.{svelte,ts}'
  ],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        etzhayyim: {
          bg: 'var(--gv2-bg-primary)',
          hover: 'var(--gv2-bg-hover)',
          input: 'var(--gv2-bg-input)',
          card: 'var(--gv2-bg-card)',
          text: 'var(--gv2-text-primary)',
          secondary: 'var(--gv2-text-secondary)',
          muted: 'var(--gv2-text-muted)',
          accent: 'var(--gv2-accent)',
          border: 'var(--gv2-border)'
        }
      }
    }
  },
  plugins: [
    etzhayyimUIKit,
    plugin(({ addBase }) => {
      addBase({
        ':root': {
          '--gv2-bg-primary': '#f5f7f9',
          '--gv2-text-primary': '#111827',
          '--gv2-text-secondary': '#6b7280',
          '--gv2-text-muted': '#9ca3af',
          '--gv2-border': '#e5e7eb',
          '--gv2-accent': '#0f766e',
          '--gv2-bg-hover': '#ebf5f4',
          '--gv2-bg-input': '#ffffff',
          '--gv2-bg-card': '#ffffff',
          '--gv2-header-height': '48px',
          '--gv2-sidebar-width': '0px',
          '--safe-area-bottom': 'env(safe-area-inset-bottom, 0px)'
        },
        'html, body': { height: '100%', overflow: 'hidden' },
        'button, input, select, textarea, a': { 'touch-action': 'manipulation' }
      });
    })
  ]
};
