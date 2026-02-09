// @ts-check

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.

 @type {import('@docusaurus/plugin-content-docs').SidebarsConfig}
 */
const sidebars = {
  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/installation',
        'getting-started/configuration',
      ],
    },
    {
      type: 'category',
      label: 'Modules',
      items: [
        'modules/intro',
        'modules/log',
        'modules/save-to-disk',
        'modules/rabbitmq',
        'modules/redis-rq',
        'modules/redis-publish',
        'modules/http-webhook',
        'modules/kafka',
        'modules/mqtt',
        'modules/websocket',
        'modules/clickhouse',
        'modules/postgresql',
        'modules/mysql',
        'modules/s3',
        'modules/aws-sqs',
        'modules/gcp-pubsub',
        'modules/activemq',
        'modules/zeromq',
      ],
    },
    {
      type: 'category',
      label: 'Authentication',
      items: [
        'authentication/intro',
        'authentication/bearer-token',
        'authentication/basic-auth',
        'authentication/jwt',
        'authentication/hmac',
        'authentication/ip-whitelist',
        'authentication/header-auth',
        'authentication/query-auth',
        'authentication/digest-auth',
        'authentication/oauth1',
        'authentication/oauth2',
        'authentication/recaptcha',
      ],
    },
    {
      type: 'category',
      label: 'Features',
      items: [
        'features/intro',
        {
          type: 'category',
          label: 'Webhook Chaining',
          items: [
            'features/webhook-chaining',
            'features/webhook-chaining-getting-started',
            'features/webhook-chaining-advanced',
            'features/webhook-chaining-troubleshooting',
          ],
        },
        {
          type: 'category',
          label: 'Webhook Connect (Cloud-to-Local Relay)',
          items: [
            'features/webhook-connect',
            'features/webhook-connect-getting-started',
            'features/webhook-connect-advanced',
            'features/webhook-connect-troubleshooting',
          ],
        },
        'features/rate-limiting',
        'features/json-schema',
        'features/credential-cleanup',
        'features/ip-whitelisting',
        'features/retry-handling',
        'features/live-config-reload',
        'features/distributed-config-etcd',
        'features/vault-secrets',
        'features/connection-pooling',
        'features/statistics',
        'features/clickhouse-analytics',
      ],
    },
  ],
};

export default sidebars;
