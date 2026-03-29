/**
 * Echo Runway — AI Fashion Content Platform
 * v2.0.0 | Cloudflare Worker
 *
 * Multi-tenant backend for AI-powered fashion content creation.
 * Features: product catalog, AI content pipeline, analytics,
 * Shopify integration, embeddable widget config, video metadata,
 * Stripe payment integration with subscription management.
 *
 * D1 Tables: tenants, products, product_images, content_jobs,
 * content_assets, environments, embed_widgets, analytics_events,
 * analytics_daily, api_keys
 *
 * Pricing: Free (5 garments) / Creator $49/mo (50) / Studio $149/mo (unlimited)
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

const ALLOWED_ORIGINS = ['https://echo-ept.com','https://www.echo-ept.com','https://echo-op.com','https://profinishusa.com','https://bgat.echo-op.com'];

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  MEDIA: R2Bucket;
  SVC_ENGINE: Fetcher;
  SVC_BRAIN: Fetcher;
  WORKER_VERSION: string;
  ECHO_API_KEY?: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  ANALYTICS: AnalyticsEngineDataset;
}

// ═══ Stripe Helpers ═══
const STRIPE_API = 'https://api.stripe.com/v1';

const PLAN_PRICE_MAP: Record<string, { price_cents: number; name: string; max_products: number }> = {
  creator: { price_cents: 4900, name: 'Echo Runway Creator', max_products: 50 },
  studio: { price_cents: 14900, name: 'Echo Runway Studio', max_products: 999999 },
};

async function stripeRequest(env: Env, path: string, method: string, body?: URLSearchParams): Promise<any> {
  const res = await fetch(`${STRIPE_API}${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body?.toString(),
  });
  const data = await res.json();
  if (!res.ok) throw new Error((data as any)?.error?.message || `Stripe API error ${res.status}`);
  return data;
}

async function verifyStripeSignature(payload: string, sigHeader: string, secret: string): Promise<boolean> {
  const parts = sigHeader.split(',').reduce((acc: Record<string, string>, part) => {
    const [k, v] = part.split('=');
    if (k && v) acc[k.trim()] = v.trim();
    return acc;
  }, {});

  const timestamp = parts['t'];
  const v1Sig = parts['v1'];
  if (!timestamp || !v1Sig) return false;

  // Replay protection: reject signatures older than 5 minutes
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload));
  const expected = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

  // Constant-time comparison
  if (expected.length !== v1Sig.length) return false;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= expected.charCodeAt(i) ^ v1Sig.charCodeAt(i);
  }
  return mismatch === 0;
}

const app = new Hono<{ Bindings: Env }>();

// ═══ Middleware ═══
app.use('*', cors({
  origin: (o) => ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Echo-API-Key', 'X-Tenant-ID'],
}));

// Auth middleware for write operations (exempts webhook paths)
function requireAuth(c: any, next: any) {
  const path = c.req.path;
  if (path.startsWith('/webhooks/')) return next();
  const key = c.req.header('X-Echo-API-Key') || c.req.header('Authorization')?.replace('Bearer ', '');
  const tenantKey = c.req.header('X-Tenant-API-Key');
  if (key === c.env.ECHO_API_KEY || tenantKey) return next();
  return c.json({ error: 'Unauthorized' }, 401);
}

// Tenant extraction
function getTenantId(c: any): string | null {
  return c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || null;
}

// ═══ Root / Health ═══
app.get('/', (c) => c.json({
  service: 'echo-runway',
  version: c.env.WORKER_VERSION || '2.0.0',
  status: 'operational',
  description: 'AI Fashion Content Platform — real-time 3D runway, AI content pipeline, analytics, Stripe payments',
  endpoints: {
    health: '/health',
    tenants: '/api/tenants',
    products: '/api/products',
    content: '/api/content',
    assets: '/api/assets',
    environments: '/api/environments',
    widgets: '/api/widgets',
    analytics: '/api/analytics',
    shopify: '/api/shopify',
    ai: '/api/ai',
    media: '/api/media',
    plans: '/plans',
    stripe_webhook: '/webhooks/stripe',
  },
  pricing: { free: '5 garments', creator: '$49/mo - 50 garments', studio: '$149/mo - unlimited' },
}));

app.get('/health', async (c) => {
  const start = Date.now();
  try {
    const r = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM tenants').first<{ cnt: number }>();
    return c.json({
      status: 'healthy',
      version: c.env.WORKER_VERSION || '2.0.0',
      latency_ms: Date.now() - start,
      tenants: r?.cnt || 0,
      stripe: !!c.env.STRIPE_SECRET_KEY,
      timestamp: new Date().toISOString(),
    });
  } catch (e: any) {
    return c.json({ status: 'degraded', error: e.message, latency_ms: Date.now() - start }, 500);
  }
});

// ═══ DB Schema Init ═══
app.get('/api/init', async (c) => {
  const key = c.req.header('X-Echo-API-Key');
  if (key !== c.env.ECHO_API_KEY) return c.json({ error: 'Unauthorized' }, 401);

  const stmts = [
    `CREATE TABLE IF NOT EXISTS tenants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      plan TEXT DEFAULT 'free',
      shopify_domain TEXT,
      shopify_token TEXT,
      brand_color TEXT DEFAULT '#14b8a6',
      brand_logo_url TEXT,
      max_products INTEGER DEFAULT 5,
      contact_email TEXT,
      website_url TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      description TEXT,
      price REAL,
      currency TEXT DEFAULT 'USD',
      category TEXT,
      sku TEXT,
      shopify_product_id TEXT,
      glb_url TEXT,
      thumbnail_url TEXT,
      status TEXT DEFAULT 'active',
      metadata TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    )`,
    `CREATE TABLE IF NOT EXISTS product_images (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      tenant_id INTEGER NOT NULL,
      url TEXT NOT NULL,
      alt_text TEXT,
      sort_order INTEGER DEFAULT 0,
      image_type TEXT DEFAULT 'photo',
      width INTEGER,
      height INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (product_id) REFERENCES products(id)
    )`,
    `CREATE TABLE IF NOT EXISTS content_jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      job_type TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      input_url TEXT,
      prompt TEXT,
      result TEXT,
      error TEXT,
      started_at TEXT,
      completed_at TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (tenant_id) REFERENCES tenants(id),
      FOREIGN KEY (product_id) REFERENCES products(id)
    )`,
    `CREATE TABLE IF NOT EXISTS content_assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      job_id INTEGER,
      asset_type TEXT NOT NULL,
      url TEXT NOT NULL,
      thumbnail_url TEXT,
      platform TEXT,
      width INTEGER,
      height INTEGER,
      duration_sec REAL,
      file_size INTEGER,
      metadata TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (tenant_id) REFERENCES tenants(id),
      FOREIGN KEY (product_id) REFERENCES products(id)
    )`,
    `CREATE TABLE IF NOT EXISTS environments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      scene_config TEXT NOT NULL,
      thumbnail_url TEXT,
      is_default INTEGER DEFAULT 0,
      is_public INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS embed_widgets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      widget_id TEXT UNIQUE NOT NULL,
      name TEXT DEFAULT 'Default Widget',
      config TEXT NOT NULL,
      allowed_domains TEXT,
      environment_id INTEGER,
      theme TEXT DEFAULT 'dark',
      autoplay INTEGER DEFAULT 1,
      show_price INTEGER DEFAULT 1,
      show_cart INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    )`,
    `CREATE TABLE IF NOT EXISTS analytics_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      product_id INTEGER,
      widget_id TEXT,
      event_type TEXT NOT NULL,
      session_id TEXT,
      visitor_hash TEXT,
      referrer TEXT,
      country TEXT,
      device TEXT,
      metadata TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE TABLE IF NOT EXISTS analytics_daily (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      product_id INTEGER,
      date TEXT NOT NULL,
      views INTEGER DEFAULT 0,
      interactions INTEGER DEFAULT 0,
      try_ons INTEGER DEFAULT 0,
      shares INTEGER DEFAULT 0,
      cart_adds INTEGER DEFAULT 0,
      video_plays INTEGER DEFAULT 0,
      avg_view_sec REAL DEFAULT 0,
      UNIQUE(tenant_id, product_id, date)
    )`,
    `CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      key_hash TEXT UNIQUE NOT NULL,
      key_prefix TEXT NOT NULL,
      name TEXT DEFAULT 'Default',
      scopes TEXT DEFAULT 'read,write',
      last_used_at TEXT,
      expires_at TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    )`,
    // Indexes
    `CREATE INDEX IF NOT EXISTS idx_products_tenant ON products(tenant_id, status)`,
    `CREATE INDEX IF NOT EXISTS idx_products_slug ON products(tenant_id, slug)`,
    `CREATE INDEX IF NOT EXISTS idx_content_jobs_tenant ON content_jobs(tenant_id, status)`,
    `CREATE INDEX IF NOT EXISTS idx_content_assets_product ON content_assets(tenant_id, product_id)`,
    `CREATE INDEX IF NOT EXISTS idx_analytics_events_tenant ON analytics_events(tenant_id, created_at)`,
    `CREATE INDEX IF NOT EXISTS idx_analytics_daily_date ON analytics_daily(tenant_id, date)`,
    `CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)`,
    `CREATE INDEX IF NOT EXISTS idx_widgets_id ON embed_widgets(widget_id)`,
  ];

  const results: string[] = [];
  for (const sql of stmts) {
    try {
      await c.env.DB.prepare(sql).run();
      results.push('OK');
    } catch (e: any) {
      results.push(`ERR: ${e.message}`);
    }
  }

  // Seed default environments
  const envCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM environments').first<{ cnt: number }>();
  if (!envCount?.cnt) {
    const defaultEnvs = [
      { name: 'Classic Runway', slug: 'classic', config: JSON.stringify({ type: 'runway', lighting: 'studio', floor: 'glossy-white', backdrop: 'gradient-dark', camera: 'tracking', music: 'fashion-beat' }), is_default: 1 },
      { name: 'Urban Street', slug: 'urban', config: JSON.stringify({ type: 'street', lighting: 'golden-hour', floor: 'concrete', backdrop: 'city-skyline', camera: 'handheld', music: 'hip-hop' }), is_default: 0 },
      { name: 'Beach Resort', slug: 'beach', config: JSON.stringify({ type: 'outdoor', lighting: 'tropical', floor: 'sand', backdrop: 'ocean-sunset', camera: 'dolly', music: 'tropical-house' }), is_default: 0 },
      { name: 'Minimalist Studio', slug: 'minimal', config: JSON.stringify({ type: 'studio', lighting: 'soft-box', floor: 'matte-gray', backdrop: 'solid-white', camera: 'static', music: 'ambient' }), is_default: 0 },
      { name: 'Neon Nightclub', slug: 'neon', config: JSON.stringify({ type: 'club', lighting: 'neon-rgb', floor: 'mirror', backdrop: 'led-wall', camera: 'orbit', music: 'electronic' }), is_default: 0 },
    ];
    for (const env of defaultEnvs) {
      await c.env.DB.prepare('INSERT INTO environments (name, slug, scene_config, is_default, is_public) VALUES (?,?,?,?,1)')
        .bind(env.name, env.slug, env.config, env.is_default).run();
    }
  }

  return c.json({ ok: true, tables: stmts.length, results, environments_seeded: !envCount?.cnt });
});

// ═══ TENANTS ═══
app.get('/api/tenants', async (c) => {
  const rows = await c.env.DB.prepare('SELECT id, name, slug, plan, max_products, contact_email, website_url, created_at FROM tenants ORDER BY created_at DESC LIMIT 100').all();
  return c.json({ ok: true, tenants: rows.results });
});

app.get('/api/tenants/:id', async (c) => {
  const id = c.req.param('id');
  const tenant = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=? OR slug=?').bind(id, id).first();
  if (!tenant) return c.json({ error: 'Tenant not found' }, 404);
  const productCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM products WHERE tenant_id=?').bind(tenant.id).first<{ cnt: number }>();
  return c.json({ ok: true, tenant, product_count: productCount?.cnt || 0 });
});

app.post('/api/tenants', async (c) => {
  const body = await c.req.json<any>();
  const { name, slug, plan, contact_email, website_url, brand_color } = body;
  if (!name || !slug) return c.json({ error: 'name and slug required' }, 400);
  const maxProducts = plan === 'studio' ? 999999 : plan === 'creator' ? 50 : 5;
  try {
    const r = await c.env.DB.prepare(
      'INSERT INTO tenants (name, slug, plan, max_products, contact_email, website_url, brand_color) VALUES (?,?,?,?,?,?,?)'
    ).bind(name, slug, plan || 'free', maxProducts, contact_email || null, website_url || null, brand_color || '#14b8a6').run();
    // Generate API key
    const keyRaw = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
    const keyPrefix = `rw_${slug.slice(0, 8)}_`;
    const fullKey = keyPrefix + keyRaw.slice(0, 32);
    const keyHash = await hashKey(fullKey);
    await c.env.DB.prepare('INSERT INTO api_keys (tenant_id, key_hash, key_prefix, name) VALUES (?,?,?,?)')
      .bind(r.meta.last_row_id, keyHash, keyPrefix, 'Default').run();
    return c.json({ ok: true, tenant_id: r.meta.last_row_id, api_key: fullKey, plan: plan || 'free', max_products: maxProducts }, 201);
  } catch (e: any) {
    if (e.message.includes('UNIQUE')) return c.json({ error: 'Slug already taken' }, 409);
    return c.json({ error: e.message }, 500);
  }
});

app.put('/api/tenants/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json<any>();
  const fields: string[] = [];
  const vals: any[] = [];
  for (const k of ['name', 'plan', 'shopify_domain', 'shopify_token', 'brand_color', 'brand_logo_url', 'contact_email', 'website_url']) {
    if (body[k] !== undefined) { fields.push(`${k}=?`); vals.push(body[k]); }
  }
  if (body.plan) {
    const maxProducts = body.plan === 'studio' ? 999999 : body.plan === 'creator' ? 50 : 5;
    fields.push('max_products=?'); vals.push(maxProducts);
  }
  if (!fields.length) return c.json({ error: 'No fields to update' }, 400);
  fields.push("updated_at=datetime('now')");
  vals.push(id);
  await c.env.DB.prepare(`UPDATE tenants SET ${fields.join(',')} WHERE id=?`).bind(...vals).run();
  return c.json({ ok: true });
});

// ═══ PRODUCTS ═══
app.get('/api/products', async (c) => {
  const tenantId = getTenantId(c);
  const category = c.req.query('category');
  const status = c.req.query('status') || 'active';
  const search = c.req.query('q');
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 200);
  const offset = parseInt(c.req.query('offset') || '0');

  let sql = 'SELECT p.*, (SELECT COUNT(*) FROM product_images WHERE product_id=p.id) as image_count, (SELECT COUNT(*) FROM content_assets WHERE product_id=p.id) as asset_count FROM products p WHERE 1=1';
  const params: any[] = [];

  if (tenantId) { sql += ' AND p.tenant_id=?'; params.push(tenantId); }
  if (status !== 'all') { sql += ' AND p.status=?'; params.push(status); }
  if (category) { sql += ' AND p.category=?'; params.push(category); }
  if (search) { sql += ' AND (p.name LIKE ? OR p.description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

  sql += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ ok: true, products: rows.results, count: rows.results?.length || 0 });
});

app.get('/api/products/:id', async (c) => {
  const id = c.req.param('id');
  const product = await c.env.DB.prepare('SELECT * FROM products WHERE id=?').bind(id).first();
  if (!product) return c.json({ error: 'Product not found' }, 404);
  const images = await c.env.DB.prepare('SELECT * FROM product_images WHERE product_id=? ORDER BY sort_order').bind(id).all();
  const assets = await c.env.DB.prepare('SELECT * FROM content_assets WHERE product_id=? ORDER BY created_at DESC LIMIT 20').bind(id).all();
  return c.json({ ok: true, product, images: images.results, assets: assets.results });
});

app.post('/api/products', async (c) => {
  const body = await c.req.json<any>();
  const { tenant_id, name, slug, description, price, currency, category, sku, glb_url, thumbnail_url } = body;
  if (!tenant_id || !name) return c.json({ error: 'tenant_id and name required' }, 400);

  // Check plan limits (downgrade expired subscriptions to free)
  const tenant = await c.env.DB.prepare('SELECT plan, max_products, plan_expires_at FROM tenants WHERE id=?').bind(tenant_id).first<{ plan: string; max_products: number; plan_expires_at: string | null }>();
  if (!tenant) return c.json({ error: 'Tenant not found' }, 404);
  let effectiveMax = tenant.max_products;
  if (tenant.plan !== 'free' && tenant.plan_expires_at && new Date(tenant.plan_expires_at) < new Date()) {
    // Subscription expired — enforce free limits
    effectiveMax = 5;
    await c.env.DB.prepare("UPDATE tenants SET plan='free', max_products=5, updated_at=datetime('now') WHERE id=?").bind(tenant_id).run();
  }
  const productCount = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM products WHERE tenant_id=? AND status=?').bind(tenant_id, 'active').first<{ cnt: number }>();
  if ((productCount?.cnt || 0) >= effectiveMax) {
    return c.json({ error: 'Product limit reached. Upgrade your plan.', current: productCount?.cnt, limit: effectiveMax, upgrade_url: '/plans/upgrade' }, 403);
  }

  const productSlug = slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '');
  const r = await c.env.DB.prepare(
    'INSERT INTO products (tenant_id, name, slug, description, price, currency, category, sku, glb_url, thumbnail_url) VALUES (?,?,?,?,?,?,?,?,?,?)'
  ).bind(tenant_id, name, productSlug, description || null, price || null, currency || 'USD', category || null, sku || null, glb_url || null, thumbnail_url || null).run();
  return c.json({ ok: true, product_id: r.meta.last_row_id }, 201);
});

app.put('/api/products/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json<any>();
  const fields: string[] = [];
  const vals: any[] = [];
  for (const k of ['name', 'slug', 'description', 'price', 'currency', 'category', 'sku', 'glb_url', 'thumbnail_url', 'status', 'metadata']) {
    if (body[k] !== undefined) { fields.push(`${k}=?`); vals.push(typeof body[k] === 'object' ? JSON.stringify(body[k]) : body[k]); }
  }
  if (!fields.length) return c.json({ error: 'No fields to update' }, 400);
  fields.push("updated_at=datetime('now')");
  vals.push(id);
  await c.env.DB.prepare(`UPDATE products SET ${fields.join(',')} WHERE id=?`).bind(...vals).run();
  return c.json({ ok: true });
});

app.delete('/api/products/:id', async (c) => {
  const id = c.req.param('id');
  await c.env.DB.prepare("UPDATE products SET status='archived', updated_at=datetime('now') WHERE id=?").bind(id).run();
  return c.json({ ok: true });
});

// ═══ PRODUCT IMAGES ═══
app.get('/api/products/:id/images', async (c) => {
  const id = c.req.param('id');
  const rows = await c.env.DB.prepare('SELECT * FROM product_images WHERE product_id=? ORDER BY sort_order').bind(id).all();
  return c.json({ ok: true, images: rows.results });
});

app.post('/api/products/:id/images', async (c) => {
  const productId = c.req.param('id');
  const body = await c.req.json<any>();
  const product = await c.env.DB.prepare('SELECT tenant_id FROM products WHERE id=?').bind(productId).first<{ tenant_id: number }>();
  if (!product) return c.json({ error: 'Product not found' }, 404);
  const { url, alt_text, sort_order, image_type, width, height } = body;
  if (!url) return c.json({ error: 'url required' }, 400);
  const r = await c.env.DB.prepare(
    'INSERT INTO product_images (product_id, tenant_id, url, alt_text, sort_order, image_type, width, height) VALUES (?,?,?,?,?,?,?,?)'
  ).bind(productId, product.tenant_id, url, alt_text || null, sort_order || 0, image_type || 'photo', width || null, height || null).run();
  return c.json({ ok: true, image_id: r.meta.last_row_id }, 201);
});

app.delete('/api/images/:id', async (c) => {
  const id = c.req.param('id');
  await c.env.DB.prepare('DELETE FROM product_images WHERE id=?').bind(id).run();
  return c.json({ ok: true });
});

// ═══ CONTENT JOBS (AI Pipeline) ═══
app.get('/api/content/jobs', async (c) => {
  const tenantId = getTenantId(c);
  const status = c.req.query('status');
  let sql = 'SELECT j.*, p.name as product_name FROM content_jobs j LEFT JOIN products p ON j.product_id=p.id WHERE 1=1';
  const params: any[] = [];
  if (tenantId) { sql += ' AND j.tenant_id=?'; params.push(tenantId); }
  if (status) { sql += ' AND j.status=?'; params.push(status); }
  sql += ' ORDER BY j.created_at DESC LIMIT 50';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ ok: true, jobs: rows.results });
});

app.get('/api/content/jobs/:id', async (c) => {
  const id = c.req.param('id');
  const job = await c.env.DB.prepare('SELECT * FROM content_jobs WHERE id=?').bind(id).first();
  if (!job) return c.json({ error: 'Job not found' }, 404);
  const assets = await c.env.DB.prepare('SELECT * FROM content_assets WHERE job_id=?').bind(id).all();
  return c.json({ ok: true, job, assets: assets.results });
});

app.post('/api/content/generate', async (c) => {
  const body = await c.req.json<any>();
  const { tenant_id, product_id, job_type, input_url, prompt } = body;
  if (!tenant_id || !product_id || !job_type) return c.json({ error: 'tenant_id, product_id, job_type required' }, 400);

  const validTypes = ['model_photo', 'social_content', 'video_thumbnail', 'product_description', 'runway_scene', 'multi_platform'];
  if (!validTypes.includes(job_type)) return c.json({ error: `Invalid job_type. Must be one of: ${validTypes.join(', ')}` }, 400);

  const r = await c.env.DB.prepare(
    'INSERT INTO content_jobs (tenant_id, product_id, job_type, status, input_url, prompt) VALUES (?,?,?,?,?,?)'
  ).bind(tenant_id, product_id, job_type, 'pending', input_url || null, prompt || null).run();

  const jobId = r.meta.last_row_id;

  // Trigger AI processing asynchronously
  try {
    await processContentJob(c.env, jobId as number, tenant_id, product_id, job_type, input_url, prompt);
  } catch (e: any) {
    await c.env.DB.prepare("UPDATE content_jobs SET status='failed', error=? WHERE id=?").bind(e.message, jobId).run();
  }

  return c.json({ ok: true, job_id: jobId, status: 'processing' }, 201);
});

// ═══ CONTENT ASSETS ═══
app.get('/api/assets', async (c) => {
  const tenantId = getTenantId(c);
  const productId = c.req.query('product_id');
  const assetType = c.req.query('type');
  const platform = c.req.query('platform');
  let sql = 'SELECT a.*, p.name as product_name FROM content_assets a LEFT JOIN products p ON a.product_id=p.id WHERE 1=1';
  const params: any[] = [];
  if (tenantId) { sql += ' AND a.tenant_id=?'; params.push(tenantId); }
  if (productId) { sql += ' AND a.product_id=?'; params.push(productId); }
  if (assetType) { sql += ' AND a.asset_type=?'; params.push(assetType); }
  if (platform) { sql += ' AND a.platform=?'; params.push(platform); }
  sql += ' ORDER BY a.created_at DESC LIMIT 100';
  const rows = await c.env.DB.prepare(sql).bind(...params).all();
  return c.json({ ok: true, assets: rows.results, count: rows.results?.length || 0 });
});

app.delete('/api/assets/:id', async (c) => {
  const id = c.req.param('id');
  const asset = await c.env.DB.prepare('SELECT url FROM content_assets WHERE id=?').bind(id).first<{ url: string }>();
  if (asset?.url?.startsWith('runway/')) {
    try { await c.env.MEDIA.delete(asset.url); } catch { /* R2 cleanup best-effort */ }
  }
  await c.env.DB.prepare('DELETE FROM content_assets WHERE id=?').bind(id).run();
  return c.json({ ok: true });
});

// ═══ ENVIRONMENTS ═══
app.get('/api/environments', async (c) => {
  const tenantId = getTenantId(c);
  let sql = 'SELECT * FROM environments WHERE is_public=1';
  const params: any[] = [];
  if (tenantId) { sql += ' OR tenant_id=?'; params.push(tenantId); }
  sql += ' ORDER BY is_default DESC, name';
  const rows = params.length
    ? await c.env.DB.prepare(sql).bind(...params).all()
    : await c.env.DB.prepare(sql).all();
  return c.json({ ok: true, environments: rows.results });
});

app.post('/api/environments', async (c) => {
  const body = await c.req.json<any>();
  const { tenant_id, name, slug, scene_config, thumbnail_url } = body;
  if (!name || !slug || !scene_config) return c.json({ error: 'name, slug, scene_config required' }, 400);
  const r = await c.env.DB.prepare(
    'INSERT INTO environments (tenant_id, name, slug, scene_config, thumbnail_url, is_public) VALUES (?,?,?,?,?,?)'
  ).bind(tenant_id || null, name, slug, typeof scene_config === 'object' ? JSON.stringify(scene_config) : scene_config, thumbnail_url || null, tenant_id ? 0 : 1).run();
  return c.json({ ok: true, environment_id: r.meta.last_row_id }, 201);
});

app.get('/api/environments/:slug', async (c) => {
  const slug = c.req.param('slug');
  const env = await c.env.DB.prepare('SELECT * FROM environments WHERE slug=? OR id=?').bind(slug, slug).first();
  if (!env) return c.json({ error: 'Environment not found' }, 404);
  return c.json({ ok: true, environment: env });
});

// ═══ EMBED WIDGETS ═══
app.get('/api/widgets', async (c) => {
  const tenantId = getTenantId(c);
  if (!tenantId) return c.json({ error: 'tenant_id required' }, 400);
  const rows = await c.env.DB.prepare('SELECT * FROM embed_widgets WHERE tenant_id=? ORDER BY created_at DESC').bind(tenantId).all();
  return c.json({ ok: true, widgets: rows.results });
});

app.post('/api/widgets', async (c) => {
  const body = await c.req.json<any>();
  const { tenant_id, name, config, allowed_domains, environment_id, theme, autoplay, show_price, show_cart } = body;
  if (!tenant_id) return c.json({ error: 'tenant_id required' }, 400);
  const widgetId = `rw_${crypto.randomUUID().slice(0, 12)}`;
  const configStr = typeof config === 'object' ? JSON.stringify(config) : (config || '{}');
  const r = await c.env.DB.prepare(
    'INSERT INTO embed_widgets (tenant_id, widget_id, name, config, allowed_domains, environment_id, theme, autoplay, show_price, show_cart) VALUES (?,?,?,?,?,?,?,?,?,?)'
  ).bind(tenant_id, widgetId, name || 'Default Widget', configStr, allowed_domains || null, environment_id || null, theme || 'dark', autoplay ?? 1, show_price ?? 1, show_cart ?? 1).run();
  return c.json({ ok: true, widget_id: widgetId, embed_code: `<script src="https://echo-runway.bmcii1976.workers.dev/widget.js?id=${widgetId}" defer></script>` }, 201);
});

app.get('/api/widgets/:widgetId', async (c) => {
  const widgetId = c.req.param('widgetId');
  const widget = await c.env.DB.prepare('SELECT w.*, t.name as tenant_name, t.brand_color, t.brand_logo_url FROM embed_widgets w LEFT JOIN tenants t ON w.tenant_id=t.id WHERE w.widget_id=?').bind(widgetId).first();
  if (!widget) return c.json({ error: 'Widget not found' }, 404);
  const products = await c.env.DB.prepare("SELECT p.*, (SELECT url FROM product_images WHERE product_id=p.id ORDER BY sort_order LIMIT 1) as primary_image FROM products p WHERE p.tenant_id=? AND p.status='active' ORDER BY p.created_at DESC").bind(widget.tenant_id).all();
  return c.json({ ok: true, widget, products: products.results });
});

// Widget JS embed script
app.get('/widget.js', async (c) => {
  const widgetId = c.req.query('id');
  if (!widgetId) return c.text('console.error("Echo Runway: missing widget id");', 400, { 'Content-Type': 'application/javascript' });

  const js = `(function(){var d=document,s=d.createElement('div');s.id='echo-runway-${widgetId}';s.style.cssText='width:100%;min-height:600px;position:relative;';var t=d.currentScript;if(t&&t.parentNode)t.parentNode.insertBefore(s,t);else d.body.appendChild(s);var shadow=s.attachShadow({mode:'open'});var f=d.createElement('iframe');f.src='https://echo-runway.bmcii1976.workers.dev/embed/${widgetId}';f.style.cssText='width:100%;height:100%;min-height:600px;border:none;';shadow.appendChild(f);})();`;
  return c.text(js, 200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'public, max-age=3600' });
});

// Embed page (served inside iframe)
app.get('/embed/:widgetId', async (c) => {
  const widgetId = c.req.param('widgetId');
  const widget = await c.env.DB.prepare('SELECT w.*, t.brand_color, t.name as brand_name FROM embed_widgets w LEFT JOIN tenants t ON w.tenant_id=t.id WHERE w.widget_id=?').bind(widgetId).first<any>();
  if (!widget) return c.html('<h2>Widget not found</h2>', 404);
  const products = await c.env.DB.prepare("SELECT id, name, slug, price, currency, thumbnail_url FROM products WHERE tenant_id=? AND status='active' LIMIT 50").bind(widget.tenant_id).all();

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${widget.brand_name || 'Echo Runway'}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0a0a;color:#fff;font-family:system-ui,-apple-system,sans-serif}.runway-container{display:flex;flex-direction:column;min-height:100vh}.canvas-area{flex:1;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0a0a0a,#1a1a2e);min-height:400px;position:relative}.placeholder{text-align:center;opacity:0.7}.placeholder h2{font-size:1.5rem;margin-bottom:0.5rem}.products-bar{display:flex;gap:12px;padding:16px;overflow-x:auto;background:#111}.product-card{flex-shrink:0;width:120px;cursor:pointer;border-radius:8px;overflow:hidden;border:2px solid transparent;transition:border-color 0.2s}.product-card:hover{border-color:${widget.brand_color||'#14b8a6'}}.product-card img{width:100%;height:120px;object-fit:cover}.product-card .info{padding:8px;font-size:12px}.product-card .name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.product-card .price{color:${widget.brand_color||'#14b8a6'};font-weight:bold;margin-top:4px}</style></head><body><div class="runway-container"><div class="canvas-area"><div class="placeholder"><h2>🎬 Echo Runway</h2><p>3D Fashion Experience Loading...</p><p style="margin-top:12px;font-size:13px;opacity:0.5">Widget: ${widgetId}</p></div></div><div class="products-bar">${(products.results || []).map((p: any) => `<div class="product-card" data-id="${p.id}"><img src="${p.thumbnail_url || 'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22120%22 height=%22120%22><rect fill=%22%23333%22 width=%22120%22 height=%22120%22/><text x=%2260%22 y=%2265%22 text-anchor=%22middle%22 fill=%22%23888%22 font-size=%2214%22>No Image</text></svg>'}" alt="${p.name}"/><div class="info"><div class="name">${p.name}</div>${p.price ? `<div class="price">${p.currency || '$'}${p.price}</div>` : ''}</div></div>`).join('')}</div></div></body></html>`;
  return c.html(html);
});

// ═══ ANALYTICS ═══
app.post('/api/analytics/event', async (c) => {
  const body = await c.req.json<any>();
  const { tenant_id, product_id, widget_id, event_type, session_id, visitor_hash, referrer, metadata } = body;
  if (!tenant_id || !event_type) return c.json({ error: 'tenant_id and event_type required' }, 400);

  const validEvents = ['view', 'interaction', 'try_on', 'share', 'cart_add', 'video_play', 'video_record', 'purchase', 'embed_load'];
  if (!validEvents.includes(event_type)) return c.json({ error: 'Invalid event_type' }, 400);

  const country = c.req.header('CF-IPCountry') || 'unknown';
  const device = detectDevice(c.req.header('User-Agent') || '');

  await c.env.DB.prepare(
    'INSERT INTO analytics_events (tenant_id, product_id, widget_id, event_type, session_id, visitor_hash, referrer, country, device, metadata) VALUES (?,?,?,?,?,?,?,?,?,?)'
  ).bind(tenant_id, product_id || null, widget_id || null, event_type, session_id || null, visitor_hash || null, referrer || null, country, device, metadata ? JSON.stringify(metadata) : null).run();

  return c.json({ ok: true });
});

app.get('/api/analytics/dashboard', async (c) => {
  const tenantId = getTenantId(c);
  if (!tenantId) return c.json({ error: 'tenant_id required' }, 400);
  const days = parseInt(c.req.query('days') || '30');
  const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

  const daily = await c.env.DB.prepare(
    'SELECT date, SUM(views) as views, SUM(interactions) as interactions, SUM(try_ons) as try_ons, SUM(shares) as shares, SUM(cart_adds) as cart_adds, SUM(video_plays) as video_plays FROM analytics_daily WHERE tenant_id=? AND date>=? GROUP BY date ORDER BY date'
  ).bind(tenantId, since).all();

  const topProducts = await c.env.DB.prepare(
    'SELECT p.name, p.id, SUM(d.views) as views, SUM(d.interactions) as interactions, SUM(d.cart_adds) as cart_adds FROM analytics_daily d JOIN products p ON d.product_id=p.id WHERE d.tenant_id=? AND d.date>=? GROUP BY d.product_id ORDER BY views DESC LIMIT 10'
  ).bind(tenantId, since).all();

  const totals = await c.env.DB.prepare(
    'SELECT SUM(views) as views, SUM(interactions) as interactions, SUM(try_ons) as try_ons, SUM(shares) as shares, SUM(cart_adds) as cart_adds, SUM(video_plays) as video_plays FROM analytics_daily WHERE tenant_id=? AND date>=?'
  ).bind(tenantId, since).first();

  const countries = await c.env.DB.prepare(
    "SELECT country, COUNT(*) as cnt FROM analytics_events WHERE tenant_id=? AND created_at>=? GROUP BY country ORDER BY cnt DESC LIMIT 10"
  ).bind(tenantId, since).all();

  const devices = await c.env.DB.prepare(
    "SELECT device, COUNT(*) as cnt FROM analytics_events WHERE tenant_id=? AND created_at>=? GROUP BY device ORDER BY cnt DESC"
  ).bind(tenantId, since).all();

  return c.json({
    ok: true,
    period: { days, since },
    totals: totals || {},
    daily: daily.results,
    top_products: topProducts.results,
    countries: countries.results,
    devices: devices.results,
  });
});

app.get('/api/analytics/product/:id', async (c) => {
  const productId = c.req.param('id');
  const days = parseInt(c.req.query('days') || '30');
  const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

  const daily = await c.env.DB.prepare(
    'SELECT * FROM analytics_daily WHERE product_id=? AND date>=? ORDER BY date'
  ).bind(productId, since).all();

  const events = await c.env.DB.prepare(
    "SELECT event_type, COUNT(*) as cnt FROM analytics_events WHERE product_id=? AND created_at>=? GROUP BY event_type ORDER BY cnt DESC"
  ).bind(productId, since).all();

  return c.json({ ok: true, daily: daily.results, event_breakdown: events.results });
});

// ═══ SHOPIFY INTEGRATION ═══
app.post('/api/shopify/import', async (c) => {
  const body = await c.req.json<any>();
  const { tenant_id } = body;
  if (!tenant_id) return c.json({ error: 'tenant_id required' }, 400);

  const tenant = await c.env.DB.prepare('SELECT shopify_domain, shopify_token, max_products FROM tenants WHERE id=?').bind(tenant_id).first<any>();
  if (!tenant?.shopify_domain || !tenant?.shopify_token) return c.json({ error: 'Shopify not configured for this tenant' }, 400);

  try {
    const res = await fetch(`https://${tenant.shopify_domain}/admin/api/2024-01/products.json?limit=250`, {
      headers: { 'X-Shopify-Access-Token': tenant.shopify_token },
    });
    if (!res.ok) return c.json({ error: `Shopify API error: ${res.status}` }, 502);
    const data = await res.json() as any;

    let imported = 0;
    for (const sp of (data.products || []).slice(0, tenant.max_products)) {
      const existing = await c.env.DB.prepare('SELECT id FROM products WHERE tenant_id=? AND shopify_product_id=?').bind(tenant_id, String(sp.id)).first();
      if (existing) continue;

      const slug = sp.handle || sp.title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
      const price = sp.variants?.[0]?.price ? parseFloat(sp.variants[0].price) : null;
      const image = sp.image?.src || sp.images?.[0]?.src || null;

      await c.env.DB.prepare(
        'INSERT INTO products (tenant_id, name, slug, description, price, category, shopify_product_id, thumbnail_url) VALUES (?,?,?,?,?,?,?,?)'
      ).bind(tenant_id, sp.title, slug, sp.body_html?.replace(/<[^>]+>/g, '').slice(0, 500) || null, price, sp.product_type || null, String(sp.id), image).run();

      // Import product images
      if (sp.images?.length) {
        const productRow = await c.env.DB.prepare('SELECT id FROM products WHERE tenant_id=? AND shopify_product_id=?').bind(tenant_id, String(sp.id)).first<{ id: number }>();
        if (productRow) {
          for (let i = 0; i < Math.min(sp.images.length, 10); i++) {
            await c.env.DB.prepare(
              'INSERT INTO product_images (product_id, tenant_id, url, alt_text, sort_order, image_type) VALUES (?,?,?,?,?,?)'
            ).bind(productRow.id, tenant_id, sp.images[i].src, sp.images[i].alt || sp.title, i, 'shopify').run();
          }
        }
      }
      imported++;
    }

    return c.json({ ok: true, imported, total_available: data.products?.length || 0, limit: tenant.max_products });
  } catch (e: any) {
    return c.json({ error: `Shopify import failed: ${e.message}` }, 500);
  }
});

app.post('/api/shopify/webhook', async (c) => {
  const topic = c.req.header('X-Shopify-Topic');
  const body = await c.req.json<any>();

  if (topic === 'products/update' || topic === 'products/create') {
    const tenantId = c.req.query('tenant_id');
    if (!tenantId) return c.json({ ok: true, skipped: 'no tenant_id' });
    const existing = await c.env.DB.prepare('SELECT id FROM products WHERE tenant_id=? AND shopify_product_id=?').bind(tenantId, String(body.id)).first<{ id: number }>();
    if (existing) {
      await c.env.DB.prepare("UPDATE products SET name=?, price=?, description=?, thumbnail_url=?, updated_at=datetime('now') WHERE id=?")
        .bind(body.title, body.variants?.[0]?.price ? parseFloat(body.variants[0].price) : null, body.body_html?.replace(/<[^>]+>/g, '').slice(0, 500) || null, body.image?.src || null, existing.id).run();
    }
  }
  return c.json({ ok: true });
});

// ═══ AI ENDPOINTS ═══
app.post('/api/ai/describe', async (c) => {
  const body = await c.req.json<any>();
  const { product_id, style, tone } = body;
  if (!product_id) return c.json({ error: 'product_id required' }, 400);

  const product = await c.env.DB.prepare('SELECT * FROM products WHERE id=?').bind(product_id).first<any>();
  if (!product) return c.json({ error: 'Product not found' }, 404);

  try {
    const prompt = `Generate a compelling ${tone || 'professional'} product description for a fashion item called "${product.name}". Category: ${product.category || 'apparel'}. Price: ${product.price ? `$${product.price}` : 'TBD'}. Style: ${style || 'modern luxury'}. Keep it under 200 words. Focus on fabric quality, fit, and styling suggestions.`;

    const aiRes = await c.env.SVC_ENGINE.fetch(new Request('https://internal/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: prompt, domain: 'GEN', max_results: 1 }),
    }));

    if (aiRes.ok) {
      const aiData = await aiRes.json() as any;
      const description = aiData.answer || aiData.results?.[0]?.content || 'Description generation in progress...';
      await c.env.DB.prepare("UPDATE products SET description=?, updated_at=datetime('now') WHERE id=?").bind(description, product_id).run();
      return c.json({ ok: true, description, source: 'engine-runtime' });
    }
    return c.json({ error: 'AI service unavailable' }, 503);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.post('/api/ai/social-captions', async (c) => {
  const body = await c.req.json<any>();
  const { product_id, platforms } = body;
  if (!product_id) return c.json({ error: 'product_id required' }, 400);

  const product = await c.env.DB.prepare('SELECT name, description, category, price FROM products WHERE id=?').bind(product_id).first<any>();
  if (!product) return c.json({ error: 'Product not found' }, 404);

  const targetPlatforms = platforms || ['instagram', 'tiktok', 'pinterest'];
  const prompt = `Generate social media captions for a fashion product called "${product.name}" (${product.category || 'apparel'}, $${product.price || 'TBD'}). Description: ${product.description || 'Fashion item'}. Generate a caption for each platform: ${targetPlatforms.join(', ')}. Include relevant hashtags. Format as JSON: {"instagram":"...","tiktok":"...","pinterest":"..."}`;

  try {
    const aiRes = await c.env.SVC_ENGINE.fetch(new Request('https://internal/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: prompt, domain: 'GEN', max_results: 1 }),
    }));

    if (aiRes.ok) {
      const aiData = await aiRes.json() as any;
      return c.json({ ok: true, captions: aiData.answer || aiData.results?.[0]?.content, platforms: targetPlatforms });
    }
    return c.json({ error: 'AI service unavailable' }, 503);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.post('/api/ai/seo-tags', async (c) => {
  const body = await c.req.json<any>();
  const { product_id } = body;
  if (!product_id) return c.json({ error: 'product_id required' }, 400);

  const product = await c.env.DB.prepare('SELECT name, description, category FROM products WHERE id=?').bind(product_id).first<any>();
  if (!product) return c.json({ error: 'Product not found' }, 404);

  const prompt = `Generate SEO-optimized tags for a fashion product: "${product.name}" (${product.category || 'apparel'}). Description: ${(product.description || '').slice(0, 200)}. Return JSON: {"title":"...(60 chars max)","meta_description":"...(155 chars max)","keywords":["tag1","tag2",...10 max],"alt_text":"...for product image"}`;

  try {
    const aiRes = await c.env.SVC_ENGINE.fetch(new Request('https://internal/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: prompt, domain: 'GEN', max_results: 1 }),
    }));

    if (aiRes.ok) {
      const aiData = await aiRes.json() as any;
      return c.json({ ok: true, seo: aiData.answer || aiData.results?.[0]?.content });
    }
    return c.json({ error: 'AI service unavailable' }, 503);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// ═══ MEDIA UPLOAD ═══
app.post('/api/media/upload', async (c) => {
  const tenantId = c.req.header('X-Tenant-ID');
  if (!tenantId) return c.json({ error: 'X-Tenant-ID header required' }, 400);

  const contentType = c.req.header('Content-Type') || 'application/octet-stream';
  const fileName = c.req.query('filename') || `upload_${Date.now()}`;
  const key = `runway/${tenantId}/${Date.now()}_${fileName}`;

  try {
    const body = await c.req.arrayBuffer();
    await c.env.MEDIA.put(key, body, {
      httpMetadata: { contentType },
      customMetadata: { tenant_id: tenantId, uploaded_at: new Date().toISOString() },
    });
    return c.json({ ok: true, key, url: `https://echo-runway.bmcii1976.workers.dev/api/media/${key}`, size: body.byteLength });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get('/api/media/*', async (c) => {
  const key = c.req.path.replace('/api/media/', '');
  const obj = await c.env.MEDIA.get(key);
  if (!obj) return c.json({ error: 'Not found' }, 404);
  const headers = new Headers();
  headers.set('Content-Type', obj.httpMetadata?.contentType || 'application/octet-stream');
  headers.set('Cache-Control', 'public, max-age=86400');
  return new Response(obj.body, { headers });
});

// ═══ API KEYS ═══
app.get('/api/keys', async (c) => {
  const tenantId = getTenantId(c);
  if (!tenantId) return c.json({ error: 'tenant_id required' }, 400);
  const rows = await c.env.DB.prepare('SELECT id, key_prefix, name, scopes, last_used_at, expires_at, created_at FROM api_keys WHERE tenant_id=?').bind(tenantId).all();
  return c.json({ ok: true, keys: rows.results });
});

app.post('/api/keys', async (c) => {
  const body = await c.req.json<any>();
  const { tenant_id, name, scopes } = body;
  if (!tenant_id) return c.json({ error: 'tenant_id required' }, 400);

  const tenant = await c.env.DB.prepare('SELECT slug FROM tenants WHERE id=?').bind(tenant_id).first<{ slug: string }>();
  if (!tenant) return c.json({ error: 'Tenant not found' }, 404);

  const keyRaw = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
  const keyPrefix = `rw_${tenant.slug.slice(0, 8)}_`;
  const fullKey = keyPrefix + keyRaw.slice(0, 32);
  const keyHash = await hashKey(fullKey);

  await c.env.DB.prepare('INSERT INTO api_keys (tenant_id, key_hash, key_prefix, name, scopes) VALUES (?,?,?,?,?)')
    .bind(tenant_id, keyHash, keyPrefix, name || 'API Key', scopes || 'read,write').run();

  return c.json({ ok: true, api_key: fullKey, prefix: keyPrefix }, 201);
});

app.delete('/api/keys/:id', async (c) => {
  const id = c.req.param('id');
  await c.env.DB.prepare('DELETE FROM api_keys WHERE id=?').bind(id).run();
  return c.json({ ok: true });
});

// ═══ STATS / OVERVIEW ═══
app.get('/api/stats', async (c) => {
  const tenantId = getTenantId(c);
  const where = tenantId ? 'WHERE tenant_id=?' : '';
  const params = tenantId ? [tenantId] : [];

  const tenants = await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM tenants').first<{ cnt: number }>();
  const products = tenantId
    ? await c.env.DB.prepare(`SELECT COUNT(*) as cnt FROM products ${where} AND status='active'`).bind(...params).first<{ cnt: number }>()
    : await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM products WHERE status='active'").first<{ cnt: number }>();
  const assets = tenantId
    ? await c.env.DB.prepare(`SELECT COUNT(*) as cnt FROM content_assets ${where}`).bind(...params).first<{ cnt: number }>()
    : await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM content_assets').first<{ cnt: number }>();
  const jobs = tenantId
    ? await c.env.DB.prepare(`SELECT COUNT(*) as cnt FROM content_jobs ${where}`).bind(...params).first<{ cnt: number }>()
    : await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM content_jobs').first<{ cnt: number }>();
  const widgets = tenantId
    ? await c.env.DB.prepare(`SELECT COUNT(*) as cnt FROM embed_widgets ${where}`).bind(...params).first<{ cnt: number }>()
    : await c.env.DB.prepare('SELECT COUNT(*) as cnt FROM embed_widgets').first<{ cnt: number }>();

  return c.json({
    ok: true,
    stats: {
      tenants: tenants?.cnt || 0,
      products: products?.cnt || 0,
      content_assets: assets?.cnt || 0,
      content_jobs: jobs?.cnt || 0,
      widgets: widgets?.cnt || 0,
    },
  });
});

// ═══ CRON: Daily Analytics Aggregation ═══
async function aggregateAnalytics(env: Env) {
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  try {
    const events = await env.DB.prepare(
      "SELECT tenant_id, product_id, event_type, COUNT(*) as cnt FROM analytics_events WHERE created_at >= ? AND created_at < ? GROUP BY tenant_id, product_id, event_type"
    ).bind(yesterday + 'T00:00:00', yesterday + 'T23:59:59').all();

    const buckets: Record<string, any> = {};
    for (const e of (events.results || []) as any[]) {
      const key = `${e.tenant_id}_${e.product_id || 0}`;
      if (!buckets[key]) buckets[key] = { tenant_id: e.tenant_id, product_id: e.product_id, views: 0, interactions: 0, try_ons: 0, shares: 0, cart_adds: 0, video_plays: 0 };
      const b = buckets[key];
      if (e.event_type === 'view' || e.event_type === 'embed_load') b.views += e.cnt;
      else if (e.event_type === 'interaction') b.interactions += e.cnt;
      else if (e.event_type === 'try_on') b.try_ons += e.cnt;
      else if (e.event_type === 'share') b.shares += e.cnt;
      else if (e.event_type === 'cart_add') b.cart_adds += e.cnt;
      else if (e.event_type === 'video_play' || e.event_type === 'video_record') b.video_plays += e.cnt;
    }

    for (const b of Object.values(buckets)) {
      await env.DB.prepare(
        'INSERT INTO analytics_daily (tenant_id, product_id, date, views, interactions, try_ons, shares, cart_adds, video_plays) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id, product_id, date) DO UPDATE SET views=excluded.views, interactions=excluded.interactions, try_ons=excluded.try_ons, shares=excluded.shares, cart_adds=excluded.cart_adds, video_plays=excluded.video_plays'
      ).bind(b.tenant_id, b.product_id, yesterday, b.views, b.interactions, b.try_ons, b.shares, b.cart_adds, b.video_plays).run();
    }

    // Cleanup old raw events (keep 7 days)
    const cutoff = new Date(Date.now() - 7 * 86400000).toISOString();
    await env.DB.prepare('DELETE FROM analytics_events WHERE created_at < ?').bind(cutoff).run();

    return { aggregated: Object.keys(buckets).length, date: yesterday };
  } catch (e: any) {
    return { error: e.message };
  }
}

// ═══ HELPERS ═══
async function hashKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function detectDevice(ua: string): string {
  if (/mobile|android|iphone|ipad/i.test(ua)) return 'mobile';
  if (/tablet|ipad/i.test(ua)) return 'tablet';
  return 'desktop';
}

async function processContentJob(env: Env, jobId: number, tenantId: number, productId: number, jobType: string, inputUrl: string | null, prompt: string | null) {
  await env.DB.prepare("UPDATE content_jobs SET status='processing', started_at=datetime('now') WHERE id=?").bind(jobId).run();

  const product = await env.DB.prepare('SELECT name, description, category FROM products WHERE id=?').bind(productId).first<any>();
  const productName = product?.name || 'Fashion Item';

  const typePrompts: Record<string, string> = {
    model_photo: `Generate a detailed description for an AI model photo shoot featuring "${productName}" (${product?.category || 'apparel'}). Include pose, lighting, background, and styling details. This will be used as a prompt for image generation.`,
    social_content: `Create a social media content brief for "${productName}". Include: 3 Instagram caption options with hashtags, 1 TikTok script (15-30 sec), 1 Pinterest description. Format as structured JSON.`,
    product_description: `Write a compelling product description for "${productName}" (${product?.category || 'apparel'}). Include key features, materials, sizing notes, and styling suggestions. Max 200 words.`,
    video_thumbnail: `Describe an eye-catching video thumbnail for a fashion runway showcase of "${productName}". Include composition, text overlay suggestions, and color scheme.`,
    runway_scene: `Design a virtual runway scene configuration for showcasing "${productName}". Include: environment type, lighting, camera angles, music mood, model walk style. Return as JSON configuration.`,
    multi_platform: `Create a complete multi-platform content package for "${productName}": Instagram post+story, TikTok video script, Pinterest pin, YouTube Shorts concept. Format each with platform-specific requirements.`,
  };

  const aiPrompt = prompt || typePrompts[jobType] || `Generate content for ${productName}`;

  try {
    const aiRes = await env.SVC_ENGINE.fetch(new Request('https://internal/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: aiPrompt, domain: 'GEN', max_results: 1 }),
    }));

    if (aiRes.ok) {
      const aiData = await aiRes.json() as any;
      const result = aiData.answer || aiData.results?.[0]?.content || 'Content generation completed';

      await env.DB.prepare("UPDATE content_jobs SET status='completed', result=?, completed_at=datetime('now') WHERE id=?")
        .bind(typeof result === 'object' ? JSON.stringify(result) : result, jobId).run();

      // Create asset record
      const platforms = jobType === 'multi_platform' ? ['instagram', 'tiktok', 'pinterest', 'youtube'] : [jobType === 'social_content' ? 'instagram' : 'general'];
      for (const platform of platforms) {
        await env.DB.prepare(
          'INSERT INTO content_assets (tenant_id, product_id, job_id, asset_type, url, platform, metadata) VALUES (?,?,?,?,?,?,?)'
        ).bind(tenantId, productId, jobId, jobType, `ai-generated://${jobId}`, platform, typeof result === 'object' ? JSON.stringify(result) : result).run();
      }
    } else {
      await env.DB.prepare("UPDATE content_jobs SET status='failed', error='AI service returned non-OK' WHERE id=?").bind(jobId).run();
    }
  } catch (e: any) {
    await env.DB.prepare("UPDATE content_jobs SET status='failed', error=? WHERE id=?").bind(e.message, jobId).run();
  }
}

// ═══ STRIPE WEBHOOK ═══
app.post('/webhooks/stripe', async (c) => {
  if (!c.env.STRIPE_SECRET_KEY || !c.env.STRIPE_WEBHOOK_SECRET) {
    return c.json({ error: 'Stripe not configured' }, 503);
  }

  const rawBody = await c.req.text();
  const sigHeader = c.req.header('Stripe-Signature') || '';
  const valid = await verifyStripeSignature(rawBody, sigHeader, c.env.STRIPE_WEBHOOK_SECRET);
  if (!valid) return c.json({ error: 'Invalid signature' }, 400);

  const event = JSON.parse(rawBody);
  const eventType = event.type as string;
  const obj = event.data?.object;

  try {
    if (eventType === 'checkout.session.completed') {
      const tenantId = obj.metadata?.tenant_id;
      const plan = obj.metadata?.plan;
      if (!tenantId || !plan) return c.json({ ok: true, skipped: 'missing metadata' });

      const cfg = PLAN_PRICE_MAP[plan];
      if (!cfg) return c.json({ ok: true, skipped: 'unknown plan' });

      const customerId = obj.customer;
      const subscriptionId = obj.subscription;
      // Subscription renews monthly — set expiry 35 days out (buffer for Stripe retries)
      const expiresAt = new Date(Date.now() + 35 * 86400000).toISOString();

      await c.env.DB.prepare(
        "UPDATE tenants SET plan=?, max_products=?, stripe_customer_id=?, stripe_subscription_id=?, plan_expires_at=?, updated_at=datetime('now') WHERE id=?"
      ).bind(plan, cfg.max_products, customerId, subscriptionId, expiresAt, tenantId).run();

      return c.json({ ok: true, action: 'plan_upgraded', tenant_id: tenantId, plan });
    }

    if (eventType === 'invoice.paid') {
      // Recurring payment succeeded — extend subscription
      const customerId = obj.customer;
      if (!customerId) return c.json({ ok: true, skipped: 'no customer' });

      const tenant = await c.env.DB.prepare('SELECT id FROM tenants WHERE stripe_customer_id=?').bind(customerId).first<{ id: number }>();
      if (tenant) {
        const expiresAt = new Date(Date.now() + 35 * 86400000).toISOString();
        await c.env.DB.prepare("UPDATE tenants SET plan_expires_at=?, updated_at=datetime('now') WHERE id=?").bind(expiresAt, tenant.id).run();
      }
      return c.json({ ok: true, action: 'subscription_renewed' });
    }

    if (eventType === 'customer.subscription.deleted') {
      // Subscription cancelled — downgrade to free
      const customerId = obj.customer;
      if (!customerId) return c.json({ ok: true, skipped: 'no customer' });

      const tenant = await c.env.DB.prepare('SELECT id FROM tenants WHERE stripe_customer_id=?').bind(customerId).first<{ id: number }>();
      if (tenant) {
        await c.env.DB.prepare(
          "UPDATE tenants SET plan='free', max_products=5, stripe_subscription_id=NULL, plan_expires_at=NULL, updated_at=datetime('now') WHERE id=?"
        ).bind(tenant.id).run();
      }
      return c.json({ ok: true, action: 'subscription_cancelled' });
    }

    return c.json({ ok: true, event: eventType, handled: false });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// ═══ PLAN MANAGEMENT ═══
app.get('/plans', async (c) => {
  const tenantId = getTenantId(c);
  if (!tenantId) return c.json({
    ok: true,
    plans: {
      free: { price: 0, max_products: 5, features: ['5 garments', 'Basic AI content', 'Analytics'] },
      creator: { price: 49, max_products: 50, features: ['50 garments', 'Full AI pipeline', 'Priority support', 'Shopify sync'] },
      studio: { price: 149, max_products: 999999, features: ['Unlimited garments', 'Full AI pipeline', 'Priority support', 'Shopify sync', 'Custom environments', 'White-label embed'] },
    },
  });

  const tenant = await c.env.DB.prepare('SELECT id, name, plan, max_products, stripe_customer_id, stripe_subscription_id, plan_expires_at FROM tenants WHERE id=? OR slug=?').bind(tenantId, tenantId).first<any>();
  if (!tenant) return c.json({ error: 'Tenant not found' }, 404);

  const productCount = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM products WHERE tenant_id=? AND status='active'").bind(tenant.id).first<{ cnt: number }>();

  // Check for expired subscription
  let currentPlan = tenant.plan;
  if (currentPlan !== 'free' && tenant.plan_expires_at && new Date(tenant.plan_expires_at) < new Date()) {
    currentPlan = 'free';
  }

  return c.json({
    ok: true,
    current: {
      plan: currentPlan,
      max_products: currentPlan === 'free' ? 5 : PLAN_PRICE_MAP[currentPlan]?.max_products || tenant.max_products,
      used_products: productCount?.cnt || 0,
      has_subscription: !!tenant.stripe_subscription_id,
      expires_at: tenant.plan_expires_at,
    },
    plans: {
      free: { price: 0, max_products: 5 },
      creator: { price: 49, max_products: 50 },
      studio: { price: 149, max_products: 999999 },
    },
  });
});

app.post('/plans/upgrade', async (c) => {
  if (!c.env.STRIPE_SECRET_KEY) return c.json({ error: 'Stripe not configured' }, 503);

  const body = await c.req.json<any>();
  const { tenant_id, plan, success_url, cancel_url } = body;
  if (!tenant_id || !plan) return c.json({ error: 'tenant_id and plan required' }, 400);

  const cfg = PLAN_PRICE_MAP[plan];
  if (!cfg) return c.json({ error: 'Invalid plan. Must be: creator or studio' }, 400);

  const tenant = await c.env.DB.prepare('SELECT id, name, slug, contact_email, stripe_customer_id FROM tenants WHERE id=? OR slug=?').bind(tenant_id, tenant_id).first<any>();
  if (!tenant) return c.json({ error: 'Tenant not found' }, 404);

  try {
    // Create or reuse Stripe customer
    let customerId = tenant.stripe_customer_id;
    if (!customerId) {
      const params = new URLSearchParams();
      params.set('name', tenant.name);
      if (tenant.contact_email) params.set('email', tenant.contact_email);
      params.set('metadata[tenant_id]', String(tenant.id));
      params.set('metadata[slug]', tenant.slug);
      const customer = await stripeRequest(c.env, '/customers', 'POST', params);
      customerId = customer.id;
      await c.env.DB.prepare("UPDATE tenants SET stripe_customer_id=?, updated_at=datetime('now') WHERE id=?").bind(customerId, tenant.id).run();
    }

    // Create a Stripe price on the fly (or use existing)
    const priceParams = new URLSearchParams();
    priceParams.set('unit_amount', String(cfg.price_cents));
    priceParams.set('currency', 'usd');
    priceParams.set('recurring[interval]', 'month');
    priceParams.set('product_data[name]', cfg.name);
    priceParams.set('product_data[metadata][plan]', plan);
    const price = await stripeRequest(c.env, '/prices', 'POST', priceParams);

    // Create Checkout Session
    const sessionParams = new URLSearchParams();
    sessionParams.set('customer', customerId);
    sessionParams.set('mode', 'subscription');
    sessionParams.set('line_items[0][price]', price.id);
    sessionParams.set('line_items[0][quantity]', '1');
    sessionParams.set('metadata[tenant_id]', String(tenant.id));
    sessionParams.set('metadata[plan]', plan);
    sessionParams.set('success_url', success_url || `https://echo-runway.bmcii1976.workers.dev/plans?tenant_id=${tenant.id}&upgraded=${plan}`);
    sessionParams.set('cancel_url', cancel_url || `https://echo-runway.bmcii1976.workers.dev/plans?tenant_id=${tenant.id}&cancelled=true`);
    const session = await stripeRequest(c.env, '/checkout/sessions', 'POST', sessionParams);

    return c.json({ ok: true, checkout_url: session.url, session_id: session.id });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// ═══ ADMIN: Stripe Migration ═══
app.post('/admin/migrate-stripe', async (c) => {
  const key = c.req.header('X-Echo-API-Key');
  if (key !== c.env.ECHO_API_KEY) return c.json({ error: 'Unauthorized' }, 401);

  const migrations = [
    "ALTER TABLE tenants ADD COLUMN stripe_customer_id TEXT",
    "ALTER TABLE tenants ADD COLUMN stripe_subscription_id TEXT",
    "ALTER TABLE tenants ADD COLUMN plan_expires_at TEXT",
    "CREATE INDEX IF NOT EXISTS idx_tenants_stripe_customer ON tenants(stripe_customer_id)",
  ];

  const results: { sql: string; status: string }[] = [];
  for (const sql of migrations) {
    try {
      await c.env.DB.prepare(sql).run();
      results.push({ sql: sql.slice(0, 60), status: 'OK' });
    } catch (e: any) {
      // "duplicate column" is expected on re-run
      results.push({ sql: sql.slice(0, 60), status: e.message.includes('duplicate') ? 'ALREADY_EXISTS' : `ERR: ${e.message}` });
    }
  }

  return c.json({ ok: true, migrations: results });
});

// ═══ EXPORT ═══
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(aggregateAnalytics(env));
  },
};
