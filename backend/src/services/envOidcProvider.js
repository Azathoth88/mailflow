import { query, withTransaction } from './db.js';
import { decrypt, encrypt, isEncrypted } from './encryption.js';
import { revokeProviderTokens, revokedTokensNote } from './apiTokens.js';

const PROVISIONING_MODES = new Set(['disabled', 'login_existing_only', 'open']);
const MASKED_SECRET = '••••••••';

// The provider columns OIDC_* set, with the variable each comes from. Settings cannot change
// these: the next start would put the environment's value back.
export const ENV_OIDC_FIELDS = {
  name: 'OIDC_NAME',
  slug: 'OIDC_SLUG',
  issuer_url: 'OIDC_ISSUER_URL',
  client_id: 'OIDC_CLIENT_ID',
  client_secret: 'OIDC_CLIENT_SECRET',
  scopes: 'OIDC_SCOPES',
  provisioning_mode: 'OIDC_PROVISIONING_MODE',
  admin_group_claim: 'OIDC_ADMIN_GROUP_CLAIM',
  admin_group_value: 'OIDC_ADMIN_GROUP_VALUE',
};

function clean(value) {
  return typeof value === 'string' ? value.trim() : '';
}

// The provider the environment describes, or null when it describes none. Throws on a
// description that cannot work, so a typo fails the start instead of hiding single sign-on.
export function readEnvOidcProvider(env = process.env) {
  const issuerUrl = clean(env.OIDC_ISSUER_URL);
  const clientId = clean(env.OIDC_CLIENT_ID);
  const clientSecret = clean(env.OIDC_CLIENT_SECRET);
  if (!issuerUrl && !clientId && !clientSecret) return null;
  if (!issuerUrl || !clientId || !clientSecret) {
    throw new Error('OIDC_ISSUER_URL, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET must be set together');
  }
  let parsed;
  try { parsed = new URL(issuerUrl); } catch {
    throw new Error(`OIDC_ISSUER_URL is not a valid URL: "${issuerUrl}"`);
  }
  if (parsed.protocol !== 'https:') throw new Error('OIDC_ISSUER_URL must use HTTPS');

  const slug = clean(env.OIDC_SLUG) || 'sso';
  if (!/^[a-z0-9-]+$/.test(slug)) {
    throw new Error(`OIDC_SLUG must contain only lowercase letters, numbers and hyphens, got "${slug}"`);
  }
  const provisioningMode = clean(env.OIDC_PROVISIONING_MODE) || 'login_existing_only';
  if (!PROVISIONING_MODES.has(provisioningMode)) {
    throw new Error(`OIDC_PROVISIONING_MODE must be one of ${[...PROVISIONING_MODES].join(', ')}, got "${provisioningMode}"`);
  }
  const adminGroupClaim = clean(env.OIDC_ADMIN_GROUP_CLAIM) || null;
  const adminGroupValue = clean(env.OIDC_ADMIN_GROUP_VALUE) || null;
  if (!adminGroupClaim !== !adminGroupValue) {
    throw new Error('OIDC_ADMIN_GROUP_CLAIM and OIDC_ADMIN_GROUP_VALUE must be set together');
  }
  return {
    name: clean(env.OIDC_NAME) || 'SSO',
    slug,
    issuer_url: issuerUrl,
    client_id: clientId,
    client_secret: clientSecret,
    scopes: clean(env.OIDC_SCOPES) || 'openid email profile',
    provisioning_mode: provisioningMode,
    admin_group_claim: adminGroupClaim,
    admin_group_value: adminGroupValue,
  };
}

export function envOidcSlug(env = process.env) {
  try {
    return readEnvOidcProvider(env)?.slug ?? null;
  } catch {
    return null;
  }
}

function plainSecret(stored) {
  return isEncrypted(stored) ? decrypt(stored) : stored;
}

// The first field in an admin's create, update or delete that would contradict the environment,
// as { field, variable }, or null. A field the request leaves out, or sends unchanged, is fine:
// Settings sends the whole form on every save.
export function envOidcConflict(provider, body = {}, env = process.env) {
  const managed = readEnvOidcProvider(env);
  if (!managed || provider?.slug !== managed.slug) return null;
  for (const [field, variable] of Object.entries(ENV_OIDC_FIELDS)) {
    if (!(field in body)) continue;
    const sent = clean(body[field]) || null;
    if (field === 'client_secret' && (!sent || sent === MASKED_SECRET)) continue;
    if (field === 'scopes' && !sent) continue;
    if (sent !== managed[field]) return { field, variable };
  }
  return null;
}

// Creates the environment's provider, or brings its row back to what the environment says.
// Enabled and the settings OIDC_* does not cover stay as an admin left them.
export async function syncEnvOidcProvider({ env = process.env, queryFn = query, transaction = withTransaction, log = console.log } = {}) {
  const managed = readEnvOidcProvider(env);
  if (!managed) return null;
  const { rows: [row] } = await queryFn('SELECT * FROM oidc_providers WHERE slug = $1', [managed.slug]);
  if (!row) {
    await queryFn(
      `INSERT INTO oidc_providers (name, slug, issuer_url, client_id, client_secret, scopes, provisioning_mode, admin_group_claim, admin_group_value)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [managed.name, managed.slug, managed.issuer_url, managed.client_id, encrypt(managed.client_secret),
        managed.scopes, managed.provisioning_mode, managed.admin_group_claim, managed.admin_group_value],
    );
    log(`SSO provider "${managed.slug}" created from the environment`);
    return 'created';
  }
  const changed = Object.keys(ENV_OIDC_FIELDS).filter(field => field !== 'slug' && (
    field === 'client_secret'
      ? plainSecret(row.client_secret) !== managed.client_secret
      : (row[field] ?? null) !== managed[field]
  ));
  if (!changed.length) return 'unchanged';
  const values = changed.map(field => (field === 'client_secret' ? encrypt(managed.client_secret) : managed[field]));
  // Another issuer or client no longer vouches for the users this one did, so the API tokens
  // confirmed through it go, as when an admin makes the change (#617). One transaction: with the
  // row updated and the tokens kept, the next start finds the row matching and never takes them.
  const identityChanged = changed.includes('issuer_url') || changed.includes('client_id');
  const revoked = await transaction(async client => {
    await client.query(
      `UPDATE oidc_providers SET ${changed.map((field, i) => `${field} = $${i + 2}`).join(', ')}, updated_at = NOW()
       WHERE slug = $1`,
      [managed.slug, ...values],
    );
    return identityChanged ? revokeProviderTokens(client, row.id) : 0;
  });
  log(`SSO provider "${managed.slug}" updated from the environment: ${changed.join(', ')}${revokedTokensNote(revoked)}`);
  return 'updated';
}
