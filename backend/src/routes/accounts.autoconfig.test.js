// GET /api/accounts/autoconfig: settings for the add-account form.
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../services/db.js', () => ({ query: vi.fn() }));
vi.mock('../middleware/auth.js', () => ({
  requireAuth: (req, _res, next) => { req.session = { userId: 'user-1' }; next(); },
}));
vi.mock('../index.js', () => ({ imapManager: {} }));
vi.mock('../services/connectionPolicy.js', () => ({ getConnectionPolicy: vi.fn() }));
vi.mock('../services/mailAutoconfig.js', async (importOriginal) => ({
  ...(await importOriginal()),
  lookupAutoconfig: vi.fn(),
}));

import express from 'express';
import accountRoutes from './accounts.js';
import { getConnectionPolicy } from '../services/connectionPolicy.js';
import { lookupAutoconfig } from '../services/mailAutoconfig.js';

let server, base;
beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api/accounts', accountRoutes);
  await new Promise(resolve => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
afterAll(async () => { await new Promise(resolve => server.close(resolve)); });
beforeEach(() => {
  lookupAutoconfig.mockReset();
  getConnectionPolicy.mockResolvedValue({ allowPrivateHosts: false, allowInsecureTls: false, allowNonstandardPorts: false });
});

const get = (qs) => fetch(`${base}/api/accounts/autoconfig${qs}`);

describe('GET /api/accounts/autoconfig', () => {
  it('returns what was found', async () => {
    lookupAutoconfig.mockResolvedValue({ source: 'ispdb', provider: 'Example', settings: { imap_host: 'imap.example.de', imap_port: 993 } });
    const res = await get('?email=max%40example.de');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ found: true, source: 'ispdb', provider: 'Example', settings: { imap_host: 'imap.example.de', imap_port: 993 } });
    expect(lookupAutoconfig).toHaveBeenCalledWith('max@example.de', { allowNonstandardPorts: false });
  });

  it('says so when nothing was found', async () => {
    lookupAutoconfig.mockResolvedValue(null);
    expect(await (await get('?email=max%40example.de')).json()).toEqual({ found: false });
  });

  it('passes on the instance\'s port policy', async () => {
    getConnectionPolicy.mockResolvedValue({ allowNonstandardPorts: true });
    lookupAutoconfig.mockResolvedValue(null);
    await get('?email=max%40example.de');
    expect(lookupAutoconfig).toHaveBeenCalledWith('max@example.de', { allowNonstandardPorts: true });
  });

  it.each(['', '?email=', '?email=a%4010.0.0.5', '?email=a%40example.de%2Fx', '?email=a@b.de&email=c@d.de'])('refuses %s', async (qs) => {
    expect((await get(qs)).status).toBe(400);
    expect(lookupAutoconfig).not.toHaveBeenCalled();
  });

  it('answers 500 without the cause when the lookup throws', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    lookupAutoconfig.mockRejectedValue(new Error('connect ECONNREFUSED 10.0.0.5:443'));
    const res = await get('?email=max%40example.de');
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: 'Autoconfig lookup failed' });
  });
});
