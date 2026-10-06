import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import nodemailer from 'nodemailer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDirectory = process.env.DATA_DIR || path.join(__dirname, '..', 'ShopFlow-RDC-data');
fs.mkdirSync(dataDirectory, { recursive: true });

const app = express();
const port = Number(process.env.PORT || 3000);
const appBaseUrl = process.env.APP_BASE_URL || `http://localhost:${port}`;
const adminEmail = (process.env.ADMIN_EMAIL || 'safarinamegabebonc@gmail.com').trim().toLowerCase();
const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_APP_PASSWORD);
const web3FormsAccessKey = process.env.WEB3FORMS_ACCESS_KEY?.trim();
const web3FormsConfigured = Boolean(web3FormsAccessKey);
const isProduction = process.env.NODE_ENV === 'production';

const db = new DatabaseSync(path.join(dataDirectory, 'shopflow.sqlite'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS shops (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    shop_id TEXT NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price INTEGER NOT NULL CHECK(price > 0),
    stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
    threshold INTEGER NOT NULL DEFAULT 5 CHECK(threshold >= 0),
    emoji TEXT NOT NULL DEFAULT '📦',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sales (
    id TEXT PRIMARY KEY,
    shop_id TEXT NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
    total INTEGER NOT NULL CHECK(total >= 0),
    is_credit INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sale_items (
    sale_id TEXT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id),
    quantity INTEGER NOT NULL CHECK(quantity > 0),
    unit_price INTEGER NOT NULL CHECK(unit_price > 0),
    PRIMARY KEY (sale_id, product_id)
  );
  CREATE TABLE IF NOT EXISTS approval_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS shops_owner_idx ON shops(owner_id);
  CREATE INDEX IF NOT EXISTS products_shop_idx ON products(shop_id);
`);

const mailer = smtpConfigured ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: process.env.SMTP_SECURE !== 'false',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_APP_PASSWORD }
}) : null;

const starterProducts = [
  ['Huile végétale 1L', 'Épicerie', 8500, 4, 12, '🛢️'],
  ['Riz Lion 25 kg', 'Épicerie', 72500, 6, 8, '🍚'],
  ['Primus 72 cl', 'Boissons', 4500, 9, 24, '🍺'],
  ['Sucre blanc 1 kg', 'Épicerie', 4200, 32, 10, '🧂'],
  ['Eau fraîche 1,5 L', 'Boissons', 2000, 48, 12, '💧'],
  ['Savon Lux', 'Maison', 3500, 21, 8, '🧼'],
  ['Lait Nido 400 g', 'Épicerie', 12500, 15, 6, '🥛'],
  ['Fanta Orange 50 cl', 'Boissons', 3000, 27, 12, '🥤']
];

const randomToken = () => crypto.randomBytes(32).toString('base64url');
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');
const asyncRoute = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
function withTransaction(operation) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = operation();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  const [algorithm, salt, expectedHex] = stored.split(':');
  if (algorithm !== 'scrypt' || !salt || !expectedHex) return false;
  const expected = Buffer.from(expectedHex, 'hex');
  const actual = crypto.scryptSync(password, salt, expected.length);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function sendCookie(res, token, maxAge) {
  const flags = [`shopflow_session=${encodeURIComponent(token)}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${maxAge}`];
  if (isProduction) flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
}

function clearCookie(res) {
  const flags = ['shopflow_session=', 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];
  if (isProduction) flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
}

const sessionMiddleware = (req, _res, next) => {
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(value => value.trim().split(/=(.*)/s).slice(0, 2)).filter(([key, value]) => key && value !== undefined));
  const rawToken = cookies.shopflow_session ? decodeURIComponent(cookies.shopflow_session) : '';
  req.user = rawToken ? db.prepare(`SELECT users.id, users.name, users.email, users.status
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ? AND users.status = 'approved'`).get(hashToken(rawToken), Date.now()) : null;
  next();
};

function requireUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Connexion requise.' });
  next();
}

function ownedShop(req, res, next) {
  const shop = db.prepare('SELECT id, owner_id AS ownerId, name FROM shops WHERE id = ? AND owner_id = ?').get(req.params.shopId, req.user.id);
  if (!shop) return res.status(404).json({ error: 'Boutique introuvable.' });
  req.shop = shop;
  next();
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function rateLimit({ limit, windowMs }) {
  const attempts = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const recent = (attempts.get(key) || []).filter(timestamp => now - timestamp < windowMs);
    if (recent.length >= limit) return res.status(429).json({ error: 'Trop de tentatives. Réessaie dans quelques minutes.' });
    recent.push(now);
    attempts.set(key, recent);
    if (attempts.size > 10000) {
      for (const [ip, times] of attempts) if (times.every(timestamp => now - timestamp >= windowMs)) attempts.delete(ip);
    }
    next();
  };
}

async function sendEmail(to, subject, text, html) {
  if (!mailer) throw new Error('SMTP_NOT_CONFIGURED');
  await mailer.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject, text, html });
}

async function sendContactWithWeb3Forms({ name, email, subject, message }) {
  const response = await fetch('https://api.web3forms.com/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ access_key: web3FormsAccessKey, name, email, subject, message, replyto: email })
  });
  const result = await response.json().catch(() => null);
  if (!response.ok || result?.success !== true) throw new Error('WEB3FORMS_DELIVERY_FAILED');
}

function approvalPage(token, name, email) {
  const safeName = escapeHTML(name);
  const safeEmail = escapeHTML(email);
  return `<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Demande ShopFlow RDC</title><style>body{font:16px system-ui;background:#f4f6ef;color:#193b2e;margin:0;min-height:100vh;display:grid;place-items:center}.box{background:white;max-width:520px;margin:20px;padding:30px;border:1px solid #e2e8dd;border-radius:8px}h1{font-size:22px}.muted{color:#65756a;line-height:1.6}.actions{display:flex;gap:10px;margin-top:24px}button{border:0;border-radius:5px;padding:12px 16px;font-weight:700;cursor:pointer}.approve{background:#216c4d;color:white}.reject{background:#f5e8e3;color:#9e4c3a}</style><main class="box"><h1>Demande d’accès ShopFlow RDC</h1><p class="muted">Le compte de <b>${safeName}</b> (${safeEmail}) attend ton approbation. Cette action permettra à la personne de se connecter à ses boutiques.</p><form method="post" action="/api/admin/approval"><input type="hidden" name="token" value="${escapeHTML(token)}"><div class="actions"><button class="approve" name="decision" value="approve">Approuver le compte</button><button class="reject" name="decision" value="reject">Refuser</button></div></form><p class="muted">Ce lien ne peut être utilisé qu’une fois et expire après 24 heures.</p></main></html>`;
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], formAction: ["'self'"], baseUri: ["'self'"] } } }));
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '8kb' }));
app.use(sessionMiddleware);

app.get('/api/health', (_req, res) => res.json({ status: 'ok', emailConfigured: Boolean(mailer), contactEmailProvider: web3FormsConfigured ? 'web3forms' : mailer ? 'smtp' : 'none' }));

app.post('/api/auth/register', rateLimit({ limit: 5, windowMs: 15 * 60 * 1000 }), asyncRoute(async (req, res) => {
  const { name, email, password, shopName } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100 || typeof shopName !== 'string' || shopName.trim().length < 2 || shopName.trim().length > 100 || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof password !== 'string' || password.length < 10 || password.length > 200) {
    return res.status(400).json({ error: 'Vérifie le nom, l’adresse e-mail, la boutique et le mot de passe (10 caractères minimum).' });
  }
  if (!mailer) return res.status(503).json({ error: 'L’envoi Gmail n’est pas configuré sur le serveur. Aucun compte n’a été créé.' });
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email.trim().toLowerCase())) return res.status(409).json({ error: 'Cette adresse e-mail a déjà une demande ou un compte.' });

  const userId = crypto.randomUUID();
  const shopId = crypto.randomUUID();
  const token = randomToken();
  const tokenHash = hashToken(token);
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
  const createRequest = () => withTransaction(() => {
    db.prepare('INSERT INTO users (id, name, email, password_hash, status) VALUES (?, ?, ?, ?, ?)').run(userId, name.trim(), email.trim().toLowerCase(), hashPassword(password), 'pending');
    db.prepare('INSERT INTO shops (id, owner_id, name) VALUES (?, ?, ?)').run(shopId, userId, shopName.trim());
    db.prepare('INSERT INTO approval_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(tokenHash, userId, expiresAt);
    const insertProduct = db.prepare('INSERT INTO products (id, shop_id, name, category, price, stock, threshold, emoji) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    for (const [productName, category, price, stock, threshold, emoji] of starterProducts) insertProduct.run(crypto.randomUUID(), shopId, productName, category, price, stock, threshold, emoji);
  });
  createRequest();

  const approvalUrl = `${appBaseUrl}/approval?token=${encodeURIComponent(token)}`;
  const safeName = escapeHTML(name.trim());
  try {
    await sendEmail(adminEmail, 'ShopFlow RDC : demande de création de compte', `Nouvelle demande de ${name.trim()} (${email.trim()}) pour la boutique « ${shopName.trim()} ». Approuver ou refuser dans les 24 heures : ${approvalUrl}`, `<p>Nouvelle demande de <b>${safeName}</b> (${escapeHTML(email.trim())}) pour la boutique <b>${escapeHTML(shopName.trim())}</b>.</p><p><a href="${approvalUrl}">Examiner et confirmer la demande</a></p><p>Le lien expire après 24 heures et ne peut être utilisé qu’une fois.</p>`);
  } catch (error) {
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    console.error('Could not notify account approver:', error.message);
    return res.status(503).json({ error: 'La demande n’a pas été enregistrée car la notification par e-mail a échoué. Vérifie la configuration SMTP.' });
  }
  res.status(202).json({ status: 'pending', message: 'Demande envoyée. L’accès sera ouvert après confirmation du créateur.' });
}));

app.get('/approval', (req, res) => {
  const token = typeof req.query.token === 'string' ? req.query.token : '';
  const request = token ? db.prepare(`SELECT users.name, users.email FROM approval_tokens JOIN users ON users.id = approval_tokens.user_id
    WHERE approval_tokens.token_hash = ? AND approval_tokens.used_at IS NULL AND approval_tokens.expires_at > ? AND users.status = 'pending'`).get(hashToken(token), Date.now()) : null;
  res.setHeader('Cache-Control', 'no-store');
  if (!request) return res.status(410).send('<!doctype html><meta charset="utf-8"><title>Lien expiré</title><p>Ce lien d’approbation est expiré ou déjà utilisé.</p>');
  res.type('html').send(approvalPage(token, request.name, request.email));
});

app.post('/api/admin/approval', asyncRoute(async (req, res) => {
  const { token, decision } = req.body || {};
  if (typeof token !== 'string' || !['approve', 'reject'].includes(decision)) return res.status(400).send('Décision invalide.');
  const tokenHash = hashToken(token);
  const outcome = decision === 'approve' ? 'approved' : 'rejected';
  const review = () => withTransaction(() => {
    const request = db.prepare(`SELECT users.id, users.name, users.email FROM approval_tokens JOIN users ON users.id = approval_tokens.user_id
      WHERE approval_tokens.token_hash = ? AND approval_tokens.used_at IS NULL AND approval_tokens.expires_at > ? AND users.status = 'pending'`).get(tokenHash, Date.now());
    if (!request) return null;
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run(outcome, request.id);
    db.prepare('UPDATE approval_tokens SET used_at = ? WHERE token_hash = ?').run(Date.now(), tokenHash);
    return request;
  });
  const request = review();
  if (!request) return res.status(410).send('<!doctype html><meta charset="utf-8"><title>Lien expiré</title><p>Ce lien a déjà été utilisé ou a expiré.</p>');
  const approvedText = 'Ta demande ShopFlow RDC a été approuvée. Tu peux maintenant te connecter.';
  const rejectedText = 'Ta demande de compte ShopFlow RDC n’a pas été approuvée.';
  let notified = true;
  try {
    await sendEmail(request.email, `ShopFlow RDC : demande ${decision === 'approve' ? 'approuvée' : 'refusée'}`, decision === 'approve' ? approvedText : rejectedText, `<p>Bonjour ${escapeHTML(request.name)},</p><p>${decision === 'approve' ? approvedText : rejectedText}</p>${decision === 'approve' ? `<p><a href="${appBaseUrl}">Ouvrir ShopFlow RDC</a></p>` : ''}`);
  } catch (error) {
    notified = false;
    console.error('Could not notify account owner:', error.message);
  }
  const result = decision === 'approve' ? 'Compte approuvé.' : 'Demande refusée.';
  res.type('html').send(`<!doctype html><meta charset="utf-8"><title>Décision enregistrée</title><p>${result} ${notified ? 'Un e-mail a été envoyé à la personne.' : 'La notification par e-mail a échoué.'}</p>`);
}));

app.post('/api/auth/login', rateLimit({ limit: 10, windowMs: 15 * 60 * 1000 }), (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Adresse e-mail et mot de passe requis.' });
  const user = db.prepare('SELECT id, name, email, password_hash AS passwordHash, status FROM users WHERE email = ?').get(email.trim().toLowerCase());
  if (!user || !verifyPassword(password, user.passwordHash)) return res.status(401).json({ error: 'Adresse e-mail ou mot de passe incorrect.' });
  if (user.status === 'pending') return res.status(403).json({ status: 'pending', error: 'Ta demande attend encore l’approbation du créateur.' });
  if (user.status !== 'approved') return res.status(403).json({ error: 'Ce compte n’a pas été approuvé.' });
  const token = randomToken();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(hashToken(token), user.id, expiresAt);
  sendCookie(res, token, 7 * 24 * 60 * 60);
  res.json({ user: { id: user.id, name: user.name, email: user.email } });
});

app.get('/api/auth/me', requireUser, (req, res) => {
  const shops = db.prepare('SELECT id, name FROM shops WHERE owner_id = ? ORDER BY created_at, rowid').all(req.user.id);
  res.json({ user: req.user, shops });
});

app.post('/api/auth/logout', (req, res) => {
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(value => value.trim().split(/=(.*)/s).slice(0, 2)).filter(([key, value]) => key && value !== undefined));
  if (cookies.shopflow_session) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(decodeURIComponent(cookies.shopflow_session)));
  clearCookie(res);
  res.status(204).end();
});

app.post('/api/contact', rateLimit({ limit: 5, windowMs: 60 * 60 * 1000 }), asyncRoute(async (req, res) => {
  const { name, email, subject, message } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 100 || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof subject !== 'string' || subject.trim().length < 3 || subject.length > 150 || typeof message !== 'string' || message.trim().length < 10 || message.length > 5000) {
    return res.status(400).json({ error: 'Vérifie les champs du formulaire et la longueur de ton message.' });
  }
  try {
    if (web3FormsConfigured) {
      await sendContactWithWeb3Forms({ name: name.trim(), email: email.trim(), subject: subject.trim(), message: message.trim() });
    } else {
      if (!mailer) return res.status(503).json({ error: 'Configure WEB3FORMS_ACCESS_KEY dans .env pour activer le formulaire de contact.' });
      await sendEmail(adminEmail, `ShopFlow RDC : ${subject.trim()}`, `Message de ${name.trim()} <${email.trim()}>\n\n${message.trim()}`, `<p>Message de <b>${escapeHTML(name.trim())}</b> &lt;${escapeHTML(email.trim())}&gt;</p><p><b>${escapeHTML(subject.trim())}</b></p><p>${escapeHTML(message.trim()).replace(/\n/g, '<br>')}</p>`);
    }
  } catch (error) {
    console.error('Could not send contact message:', error.message);
    return res.status(503).json({ error: web3FormsConfigured ? 'Web3Forms n’a pas accepté le message. Vérifie la clé d’accès et la configuration de ton compte.' : 'Le message n’a pas pu être envoyé. Vérifie la configuration SMTP du serveur.' });
  }
  res.status(202).json({ message: 'Message envoyé. Merci de nous avoir contactés.' });
}));

app.use('/api/shops', requireUser);
app.get('/api/shops', (req, res) => res.json(db.prepare('SELECT id, name FROM shops WHERE owner_id = ? ORDER BY created_at, rowid').all(req.user.id)));
app.post('/api/shops', (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'Le nom de boutique doit contenir entre 2 et 100 caractères.' });
  const shopId = crypto.randomUUID();
  db.prepare('INSERT INTO shops (id, owner_id, name) VALUES (?, ?, ?)').run(shopId, req.user.id, name);
  res.status(201).json({ id: shopId, name });
});
app.patch('/api/shops/:shopId', ownedShop, (req, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  if (name.length < 2 || name.length > 100) return res.status(400).json({ error: 'Le nom de boutique doit contenir entre 2 et 100 caractères.' });
  db.prepare('UPDATE shops SET name = ? WHERE id = ? AND owner_id = ?').run(name, req.shop.id, req.user.id);
  res.json({ id: req.shop.id, name });
});
app.get('/api/shops/:shopId/products', ownedShop, (req, res) => {
  res.json(db.prepare('SELECT id, name, category, price, stock, threshold, emoji FROM products WHERE shop_id = ? ORDER BY created_at, rowid').all(req.shop.id));
});
app.post('/api/shops/:shopId/products', ownedShop, (req, res) => {
  const { name, category, price, stock = 0, threshold = 5, emoji = '📦' } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 1 || name.length > 120 || typeof category !== 'string' || category.length > 80 || !Number.isSafeInteger(price) || price < 1 || !Number.isSafeInteger(stock) || stock < 0 || !Number.isSafeInteger(threshold) || threshold < 0 || typeof emoji !== 'string' || emoji.length > 12) return res.status(400).json({ error: 'Données produit invalides.' });
  const product = { id: crypto.randomUUID(), name: name.trim(), category, price, stock, threshold, emoji };
  db.prepare('INSERT INTO products (id, shop_id, name, category, price, stock, threshold, emoji) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(product.id, req.shop.id, product.name, product.category, product.price, product.stock, product.threshold, product.emoji);
  res.status(201).json(product);
});
app.patch('/api/shops/:shopId/products/:productId', ownedShop, (req, res) => {
  const { name, category, price, stock, threshold, emoji } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 1 || name.length > 120 || typeof category !== 'string' || category.length > 80 || !Number.isSafeInteger(price) || price < 1 || !Number.isSafeInteger(stock) || stock < 0 || !Number.isSafeInteger(threshold) || threshold < 0 || typeof emoji !== 'string' || emoji.length > 12) return res.status(400).json({ error: 'Données produit invalides.' });
  const result = db.prepare('UPDATE products SET name = ?, category = ?, price = ?, stock = ?, threshold = ?, emoji = ? WHERE id = ? AND shop_id = ?').run(name.trim(), category, price, stock, threshold, emoji, req.params.productId, req.shop.id);
  if (!result.changes) return res.status(404).json({ error: 'Produit introuvable.' });
  res.json({ id: req.params.productId, name: name.trim(), category, price, stock, threshold, emoji });
});
app.post('/api/shops/:shopId/sales', ownedShop, (req, res) => {
  const { items, isCredit = false } = req.body || {};
  if (!Array.isArray(items) || items.length < 1 || items.length > 100 || typeof isCredit !== 'boolean') return res.status(400).json({ error: 'Contenu de vente invalide.' });
  const mergedItems = new Map();
  for (const item of items) {
    if (typeof item?.productId !== 'string' || !Number.isSafeInteger(item.quantity) || item.quantity < 1) return res.status(400).json({ error: 'Article de vente invalide.' });
    mergedItems.set(item.productId, (mergedItems.get(item.productId) || 0) + item.quantity);
  }
  const saleId = crypto.randomUUID();
  try {
    const result = withTransaction(() => {
      let total = 0;
      const saleLines = [];
      for (const [productId, quantity] of mergedItems) {
        const product = db.prepare('SELECT id, price, stock FROM products WHERE id = ? AND shop_id = ?').get(productId, req.shop.id);
        if (!product) throw new Error('PRODUCT_NOT_FOUND');
        if (product.stock < quantity) throw new Error('INSUFFICIENT_STOCK');
        db.prepare('UPDATE products SET stock = stock - ? WHERE id = ? AND shop_id = ? AND stock >= ?').run(quantity, productId, req.shop.id, quantity);
        total += product.price * quantity;
        saleLines.push({ productId, quantity, unitPrice: product.price });
      }
      db.prepare('INSERT INTO sales (id, shop_id, total, is_credit) VALUES (?, ?, ?, ?)').run(saleId, req.shop.id, total, isCredit ? 1 : 0);
      const addLine = db.prepare('INSERT INTO sale_items (sale_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)');
      for (const line of saleLines) addLine.run(saleId, line.productId, line.quantity, line.unitPrice);
      const summary = db.prepare(`SELECT COALESCE(SUM(total), 0) AS salesToday, COUNT(*) AS saleCount
        FROM sales WHERE shop_id = ? AND date(created_at) = date('now')`).get(req.shop.id);
      return { total, saleCount: summary.saleCount, salesToday: summary.salesToday };
    });
    res.status(201).json({ id: saleId, ...result });
  } catch (error) {
    if (error.message === 'INSUFFICIENT_STOCK') return res.status(409).json({ error: 'Stock insuffisant pour finaliser cette vente.' });
    if (error.message === 'PRODUCT_NOT_FOUND') return res.status(404).json({ error: 'Un produit de cette vente n’existe plus dans cette boutique.' });
    throw error;
  }
});

app.use(express.static(__dirname, { extensions: ['html'] }));
app.use((error, _req, res, _next) => {
  console.error(error);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Une erreur interne est survenue.' });
});

app.listen(port, () => {
  console.log(`ShopFlow RDC listening at ${appBaseUrl}`);
  console.log(`Approval notifications: ${adminEmail}`);
  if (!mailer) console.warn('SMTP is not configured. Account registration stays disabled until .env is configured.');
});
