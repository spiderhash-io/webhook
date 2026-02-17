// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

import {themes as prismThemes} from 'prism-react-renderer';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Core Webhook Module',
  tagline: 'Flexible and configurable webhook receiver and processor',
  favicon: 'img/favicon.ico',

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // Set the production url of your site here
  url: 'https://spiderhash.io',
  // Set the /<baseUrl>/ pathname under which your site is served
  // This site will live under /docs/
  baseUrl: '/docs/',

  // GitHub pages deployment config.
  organizationName: 'spiderhash-io',
  projectName: 'core-webhook-module',

  onBrokenLinks: 'warn', // Changed to warn to allow build with redirects

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          routeBasePath: '/', // Serve docs at the root of /docs/
          editUrl:
            'https://github.com/spiderhash-io/core-webhook-module/tree/main/docusaurus/',
        },
        blog: false, // Disable blog - only documentation
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/social-card.jpg',
      colorMode: {
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'Core Webhook Module',
        logo: {
          alt: 'Core Webhook Module Logo',
          src: 'img/logo.svg',
          // Logo will link to home (first doc) by default
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Documentation',
          },
          {
            href: 'https://spiderhash.io',
            label: 'Spiderhash.io',
            position: 'left',
          },
          {
            href: 'https://github.com/spiderhash-io',
            label: 'GitHub',
            position: 'right',
          }
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Introduction',
                to: '/',
              },
              {
                label: 'Getting Started',
                to: '/getting-started/installation',
              },
              {
                label: 'Modules',
                to: '/modules/intro',
              },
              {
                label: 'Authentication',
                to: '/authentication/intro',
              },
            ],
          },
          {
            title: 'Links',
            items: [
              {
                label: 'Spiderhash.io',
                href: 'https://spiderhash.io',
              },
              {
                label: 'GitHub',
                href: 'https://github.com/spiderhash-io',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Core Webhook Module.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
      },
    }),
};

export default config;
