import { themes as prismThemes } from 'prism-react-renderer';
import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title:   'ezone',
  tagline: 'Military-grade passwordless authentication SDK',
  favicon: 'img/favicon.ico',
  url:     'https://docs.ezone.dev',
  baseUrl: '/',

  organizationName: 'ezone-sdk',
  projectName:      'ezone-sdk',

  onBrokenLinks:        'throw',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales:       ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath:     './sidebars.ts',
          editUrl: 'https://github.com/ezone-sdk/ezone-sdk/edit/main/docs/',
          showLastUpdateTime: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/ezone-social-card.png',

    announcementBar: {
      id:              'beta',
      content:         '🚀 ezone v0.1.0 is now in public beta — <a href="/docs/getting-started">get started in 5 minutes</a>',
      backgroundColor: '#0f172a',
      textColor:       '#38bdf8',
      isCloseable:     true,
    },

    colorMode: {
      defaultMode:              'dark',
      disableSwitch:             false,
      respectPrefersColorScheme: true,
    },

    navbar: {
      title: 'ezone',
      logo: {
        alt: 'ezone logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type:      'docSidebar',
          sidebarId: 'mainSidebar',
          position:  'left',
          label:     'Docs',
        },
        {
          to:       '/docs/api-reference',
          label:    'API Reference',
          position: 'left',
        },
        {
          to:       '/docs/sdks',
          label:    'SDKs',
          position: 'left',
        },
        {
          href:     'https://github.com/ezone-sdk/ezone-sdk',
          label:    'GitHub',
          position: 'right',
        },
        {
          type:     'docsVersionDropdown',
          position: 'right',
        },
      ],
    },

    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            { label: 'Getting Started', to: '/docs/getting-started' },
            { label: 'API Reference',   to: '/docs/api-reference' },
            { label: 'SDKs',            to: '/docs/sdks' },
          ],
        },
        {
          title: 'SDKs',
          items: [
            { label: 'Node.js',  to: '/docs/sdks/nodejs' },
            { label: 'Python',   to: '/docs/sdks/python' },
            { label: 'Go',       to: '/docs/sdks/go' },
            { label: 'Browser',  to: '/docs/sdks/browser' },
          ],
        },
        {
          title: 'Community',
          items: [
            { label: 'GitHub',  href: 'https://github.com/ezone-sdk/ezone-sdk' },
            { label: 'Issues',  href: 'https://github.com/ezone-sdk/ezone-sdk/issues' },
          ],
        },
      ],
      copyright: `© ${new Date().getFullYear()} ezone SDK. Built with C++ and OpenSSL.`,
    },

    prism: {
      theme:                prismThemes.nightOwlLight,
      darkTheme:            prismThemes.nightOwl,
      additionalLanguages: [
        'bash', 'cpp', 'python', 'go', 'rust', 'java',
        'swift', 'dart', 'php', 'ruby', 'csharp',
      ],
    },

    algolia: {
      appId:     'YOUR_APP_ID',
      apiKey:    'YOUR_API_KEY',
      indexName: 'ezone',
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
