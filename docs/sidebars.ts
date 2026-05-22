import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  mainSidebar: [
    {
      type: 'doc',
      id:   'intro',
      label: 'Introduction',
    },
    {
      type:  'doc',
      id:    'getting-started',
      label: 'Getting Started',
    },
    {
      type:  'category',
      label: 'Core Concepts',
      collapsed: false,
      items: [
        'concepts/architecture',
        'concepts/cryptography',
        'concepts/stateless-auth',
        'concepts/device-keys',
      ],
    },
    {
      type:  'category',
      label: 'SDKs',
      collapsed: false,
      items: [
        'sdks/index',
        'sdks/nodejs',
        'sdks/python',
        'sdks/go',
        'sdks/browser',
        'sdks/rust',
        'sdks/java',
        'sdks/dart',
        'sdks/swift',
        'sdks/dotnet',
        'sdks/php',
        'sdks/ruby',
      ],
    },
    {
      type:  'doc',
      id:    'api-reference',
      label: 'API Reference',
    },
    {
      type:  'category',
      label: 'Self-Hosting',
      items: [
        'self-hosting/server',
        'self-hosting/configuration',
        'self-hosting/tls',
      ],
    },
    {
      type:  'category',
      label: 'Security',
      items: [
        'security/overview',
        'security/fips',
        'security/threat-model',
      ],
    },
  ],
};

export default sidebars;
