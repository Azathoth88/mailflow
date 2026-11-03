import { describe, it, expect, vi } from 'vitest';

vi.mock('./db.js', () => ({ query: vi.fn(), withTransaction: vi.fn() }));
vi.mock('./encryption.js', () => ({
  encrypt: v => `enc:v1:${v}`,
  decrypt: v => v.replace(/^enc:v1:/, ''),
  isEncrypted: v => typeof v === 'string' && v.startsWith('enc:v1:'),
}));

const { readEnvOidcProvider, envOidcSlug, envOidcConflict, syncEnvOidcProvider } = await import('./envOidcProvider.js');

const ENV = {
  OIDC_ISSUER_URL: 'https://sso.example.com/application/o/mailflow/',
  OIDC_CLIENT_ID: 'mailflow',
  OIDC_CLIENT_SECRET: 's3cret',
};

// The row the environment above describes, as the table holds it.
const ROW = {
  id: 'p1', name: 'SSO', slug: 'sso', issuer_url: ENV.OIDC_ISSUER_URL, client_id: 'mailflow',
  client_secret: 'enc:v1:s3cret', scopes: 'openid email profile', provisioning_mode: 'login_existing_only',
  admin_group_claim: null, admin_group_value: null, enabled: false, allowed_domains: 'example.com',
};

describe('readEnvOidcProvider', () => {
  it('describes no provider when none of the three required variables is set', () => {
    expect(readEnvOidcProvider({})).toBeNull();
    expect(readEnvOidcProvider({ OIDC_NAME: 'Company SSO', OIDC_ISSUER_URL: '  ' })).toBeNull();
  });

  it('fills the optional fields with the defaults Settings uses', () => {
    expect(readEnvOidcProvider(ENV)).toEqual({
      name: 'SSO', slug: 'sso', issuer_url: ENV.OIDC_ISSUER_URL, client_id: 'mailflow', client_secret: 's3cret',
      scopes: 'openid email profile', provisioning_mode: 'login_existing_only',
      admin_group_claim: null, admin_group_value: null,
    });
  });

  it('takes every optional field from its variable', () => {
    expect(readEnvOidcProvider({
      ...ENV, OIDC_NAME: 'Company SSO', OIDC_SLUG: 'company', OIDC_SCOPES: 'openid email profile groups',
      OIDC_PROVISIONING_MODE: 'open', OIDC_ADMIN_GROUP_CLAIM: 'groups', OIDC_ADMIN_GROUP_VALUE: 'mail-admins',
    })).toMatchObject({
      name: 'Company SSO', slug: 'company', scopes: 'openid email profile groups', provisioning_mode: 'open',
      admin_group_claim: 'groups', admin_group_value: 'mail-admins',
    });
  });

  it.each([
    [{ OIDC_ISSUER_URL: ENV.OIDC_ISSUER_URL }, /must be set together/],
    [{ ...ENV, OIDC_CLIENT_SECRET: '' }, /must be set together/],
    [{ ...ENV, OIDC_ISSUER_URL: 'sso.example.com' }, /not a valid URL/],
    [{ ...ENV, OIDC_ISSUER_URL: 'http://sso.example.com' }, /HTTPS/],
    [{ ...ENV, OIDC_SLUG: 'Company SSO' }, /OIDC_SLUG/],
    [{ ...ENV, OIDC_PROVISIONING_MODE: 'everyone' }, /OIDC_PROVISIONING_MODE/],
    [{ ...ENV, OIDC_ADMIN_GROUP_CLAIM: 'groups' }, /OIDC_ADMIN_GROUP_VALUE/],
  ])('refuses a description that cannot work: %o', (env, message) => {
    expect(() => readEnvOidcProvider(env)).toThrow(message);
    expect(envOidcSlug(env)).toBeNull();
  });
});

describe('envOidcConflict', () => {
  it('lets Settings save the form unchanged, the secret masked or left out', () => {
    const form = {
      name: 'SSO', slug: 'sso', issuer_url: ENV.OIDC_ISSUER_URL, client_id: 'mailflow', scopes: 'openid email profile',
      provisioning_mode: 'login_existing_only', admin_group_claim: null, admin_group_value: null,
      enabled: false, allowed_domains: 'example.org', require_email_verified: false,
    };
    expect(envOidcConflict(ROW, form, ENV)).toBeNull();
    expect(envOidcConflict(ROW, { ...form, client_secret: '••••••••' }, ENV)).toBeNull();
    expect(envOidcConflict(ROW, { ...form, client_secret: 's3cret' }, ENV)).toBeNull();
  });

  it('names the variable behind a field the save would change', () => {
    expect(envOidcConflict(ROW, { issuer_url: 'https://other.example.com/' }, ENV))
      .toEqual({ field: 'issuer_url', variable: 'OIDC_ISSUER_URL' });
    expect(envOidcConflict(ROW, { client_secret: 'new-secret' }, ENV))
      .toEqual({ field: 'client_secret', variable: 'OIDC_CLIENT_SECRET' });
    expect(envOidcConflict(ROW, { slug: 'renamed' }, ENV)).toEqual({ field: 'slug', variable: 'OIDC_SLUG' });
    expect(envOidcConflict(ROW, { admin_group_claim: 'groups' }, ENV))
      .toEqual({ field: 'admin_group_claim', variable: 'OIDC_ADMIN_GROUP_CLAIM' });
  });

  it('leaves every other provider alone', () => {
    expect(envOidcConflict({ ...ROW, slug: 'google' }, { issuer_url: 'https://accounts.google.com' }, ENV)).toBeNull();
    expect(envOidcConflict(ROW, { issuer_url: 'https://other.example.com/' }, {})).toBeNull();
  });
});

describe('syncEnvOidcProvider', () => {
  const run = (rows, env = ENV) => {
    const queryFn = vi.fn(async sql => (sql.startsWith('SELECT') ? { rows } : { rows: [] }));
    // What runs in the transaction, kept apart from queryFn so a test can see it ran there.
    const tx = { query: vi.fn(async sql => ({ rows: [], rowCount: sql.startsWith('DELETE') ? 2 : 1 })) };
    const transaction = vi.fn(async fn => fn(tx));
    const log = vi.fn();
    return syncEnvOidcProvider({ env, queryFn, transaction, log }).then(result => ({ result, queryFn, tx, log }));
  };
  const statements = tx => tx.query.mock.calls.map(([sql]) => sql.trim().split(/\s+/).slice(0, 3).join(' '));

  it('does nothing when the environment describes no provider', async () => {
    const { result, queryFn } = await run([], {});
    expect(result).toBeNull();
    expect(queryFn).not.toHaveBeenCalled();
  });

  it('creates the provider with the secret encrypted', async () => {
    const { result, queryFn } = await run([]);
    expect(result).toBe('created');
    const [sql, params] = queryFn.mock.calls[1];
    expect(sql).toMatch(/^INSERT INTO oidc_providers/);
    expect(params).toEqual(['SSO', 'sso', ENV.OIDC_ISSUER_URL, 'mailflow', 'enc:v1:s3cret',
      'openid email profile', 'login_existing_only', null, null]);
  });

  it('writes nothing when the row already matches, whatever the secret was encrypted to', async () => {
    const { result, queryFn } = await run([{ ...ROW, client_secret: 'enc:v1:s3cret' }]);
    expect(result).toBe('unchanged');
    expect(queryFn).toHaveBeenCalledTimes(1);
  });

  it('updates only the fields the environment changed, and leaves enabled and the rest to the admin', async () => {
    const { result, tx } = await run([ROW], {
      ...ENV, OIDC_ISSUER_URL: 'https://sso.example.org/application/o/mailflow/', OIDC_CLIENT_SECRET: 'rotated',
    });
    expect(result).toBe('updated');
    const [sql, params] = tx.query.mock.calls[0];
    expect(sql).toMatch(/SET issuer_url = \$2, client_secret = \$3, updated_at = NOW\(\)\s+WHERE slug = \$1/);
    expect(sql).not.toMatch(/enabled|allowed_domains/);
    expect(params).toEqual(['sso', 'https://sso.example.org/application/o/mailflow/', 'enc:v1:rotated']);
  });

  // The same rule the admin route follows (#617): a provider pointed at another issuer or client no
  // longer vouches for the users it did, so the API tokens confirmed through it go with the change,
  // in the transaction that makes it. A start that changed the row but kept them would leave the row
  // matching the environment, so no later start would take them.
  it.each([
    ['issuer', { OIDC_ISSUER_URL: 'https://other-idp.example.com/' }],
    ['client', { OIDC_CLIENT_ID: 'mailflow-2' }],
  ])('takes the tokens confirmed through it along when the environment changes its %s', async (_what, change) => {
    const { result, tx, log } = await run([ROW], { ...ENV, ...change });
    expect(result).toBe('updated');
    expect(statements(tx)).toEqual(['UPDATE oidc_providers SET', 'DELETE FROM api_tokens']);
    expect(tx.query.mock.calls[1]).toEqual(['DELETE FROM api_tokens WHERE oidc_provider_id = $1', ['p1']]);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/updated from the environment: .*, and deleted 2 API tokens$/));
  });

  it('leaves the tokens through any other change, a rotated secret included', async () => {
    const { result, tx, log } = await run([ROW], { ...ENV, OIDC_NAME: 'Company SSO', OIDC_CLIENT_SECRET: 'rotated' });
    expect(result).toBe('updated');
    expect(statements(tx)).toEqual(['UPDATE oidc_providers SET']);
    expect(log).toHaveBeenCalledWith('SSO provider "sso" updated from the environment: name, client_secret');
  });
});
