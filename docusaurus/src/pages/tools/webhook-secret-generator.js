import React, {useState, useCallback} from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';

const LENGTHS = [32, 48, 64];

function generateSecret(bytes, format) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  if (format === 'hex') {
    return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  // base64url without padding: safe for headers, URLs, and env vars
  let bin = '';
  buf.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function Generator() {
  const [bytes, setBytes] = useState(32);
  const [format, setFormat] = useState('hex');
  const [secret, setSecret] = useState(() => null);
  const [copied, setCopied] = useState(false);

  const regenerate = useCallback((b, f) => {
    setSecret(generateSecret(b, f));
    setCopied(false);
  }, []);

  const copy = useCallback(() => {
    if (secret) {
      navigator.clipboard.writeText(secret).then(() => setCopied(true));
    }
  }, [secret]);

  return (
    <div
      style={{
        border: '1px solid var(--ifm-color-emphasis-300)',
        borderRadius: 8,
        padding: '1.5rem',
        marginBottom: '2rem',
      }}>
      <div style={{display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem'}}>
        <label>
          Length:{' '}
          <select
            value={bytes}
            onChange={(e) => {
              const b = Number(e.target.value);
              setBytes(b);
              if (secret) regenerate(b, format);
            }}>
            {LENGTHS.map((l) => (
              <option key={l} value={l}>
                {l} bytes
              </option>
            ))}
          </select>
        </label>
        <label>
          Format:{' '}
          <select
            value={format}
            onChange={(e) => {
              setFormat(e.target.value);
              if (secret) regenerate(bytes, e.target.value);
            }}>
            <option value="hex">hex</option>
            <option value="base64url">base64url</option>
          </select>
        </label>
        <button className="button button--primary" onClick={() => regenerate(bytes, format)}>
          Generate secret
        </button>
      </div>
      {secret && (
        <div>
          <code
            style={{
              display: 'block',
              padding: '0.75rem',
              wordBreak: 'break-all',
              marginBottom: '0.5rem',
            }}>
            {secret}
          </code>
          <button className="button button--secondary button--sm" onClick={copy}>
            {copied ? 'Copied!' : 'Copy to clipboard'}
          </button>
        </div>
      )}
    </div>
  );
}

export default function WebhookSecretGenerator() {
  return (
    <Layout
      title="Webhook Secret Generator"
      description="Free online webhook secret generator. Create cryptographically secure random secrets for HMAC signatures, bearer tokens, and API keys. Generated locally in your browser.">
      <main className="container margin-vert--lg" style={{maxWidth: 760}}>
        <h1>Webhook Secret Generator</h1>
        <p>
          Generate a cryptographically secure random secret for signing and verifying webhooks.
          Secrets are generated <strong>locally in your browser</strong> with{' '}
          <code>crypto.getRandomValues()</code>; nothing is sent to any server.
        </p>

        <Generator />

        <h2>What is a webhook secret?</h2>
        <p>
          A webhook secret is a shared random value that the webhook sender uses to sign each
          request, typically as an HMAC signature in a header such as{' '}
          <code>X-Hub-Signature-256</code> (GitHub) or <code>Stripe-Signature</code> (Stripe). The
          receiver recomputes the signature over the raw request body with the same secret and
          rejects the request when the values differ. This proves the payload came from the real
          sender and was not tampered with in transit.
        </p>

        <h2>How long should a webhook secret be?</h2>
        <p>
          At least 32 bytes (256 bits) of randomness. That matches the strength of HMAC-SHA256, the
          most common webhook signature algorithm. Longer secrets do not hurt, but 32 random bytes
          is already beyond brute force. What matters more is that the secret comes from a
          cryptographically secure random source, never from a password you made up.
        </p>

        <h2>Using the secret to verify webhooks</h2>
        <p>
          If you receive webhooks with{' '}
          <Link to="/docs/">Core Webhook Module</Link>, put the secret in an environment variable
          and reference it in your webhook configuration:
        </p>
        <pre>
          <code>{`{
  "github_events": {
    "data_type": "json",
    "module": "log",
    "hmac": {
      "secret": "{$WEBHOOK_HMAC_SECRET}",
      "header": "X-Hub-Signature-256",
      "algorithm": "sha256"
    }
  }
}`}</code>
        </pre>
        <p>
          The module verifies the HMAC with a constant-time comparison, which prevents timing
          attacks. See the{' '}
          <Link to="/docs/authentication/hmac/">HMAC signature validation guide</Link> for
          GitHub-style and Stripe-style signatures, or the{' '}
          <Link to="/docs/authentication/intro/">authentication overview</Link> for the other 11
          supported methods (JWT, OAuth, Basic, IP whitelisting, and more).
        </p>

        <h2>Tips</h2>
        <ul>
          <li>Use a different secret per webhook endpoint, so one leak never affects the rest.</li>
          <li>
            Store secrets in environment variables or a secret manager such as{' '}
            <Link to="/docs/features/vault-secrets/">HashiCorp Vault</Link>, never in code or config
            files committed to git.
          </li>
          <li>
            Rotate secrets periodically: generate a new one here, update the sender and receiver,
            then retire the old value.
          </li>
          <li>
            Hex and base64url formats encode the same randomness; pick whichever your provider's
            docs expect. Both are safe in HTTP headers and environment variables.
          </li>
        </ul>
      </main>
    </Layout>
  );
}
