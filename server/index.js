import pg from 'pg';
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
const app=express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({limit:'20kb'}));
app.use('/api',rateLimit({windowMs:15*60*1000,limit:90,standardHeaders:'draft-7',legacyHeaders:false}));
const BOT_TOKEN=process.env.TELEGRAM_BOT_TOKEN||'';
const ADMIN_ID=String(process.env.ADMIN_TELEGRAM_ID||'8465117749');
const allowedOrigins = new Set([
  'https://shahromak.github.io',
  'https://shakha-donat-store.pithymorningglory2.chatgpt.site',
  ...(process.env.ALLOWED_ORIGINS || '').split(',').map(origin => origin.trim()).filter(Boolean)
]);
app.use((req,res,next)=>{const origin=req.headers.origin;if(origin&&allowedOrigins.has(origin)){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');res.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');}if(req.method==='OPTIONS')return res.sendStatus(204);next()});
function verifyInitData(raw){if(!BOT_TOKEN||typeof raw!=='string'||raw.length>8192)throw Error('Telegram authentication unavailable');const params=new URLSearchParams(raw),hash=params.get('hash');if(!hash||!/^[0-9a-f]{64}$/i.test(hash))throw Error('Invalid Telegram signature');params.delete('hash');const check=[...params.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>k+'='+v).join('\n');const secret=crypto.createHmac('sha256','WebAppData').update(BOT_TOKEN).digest();const digest=crypto.createHmac('sha256',secret).update(check).digest();if(!crypto.timingSafeEqual(Buffer.from(hash,'hex'),digest))throw Error('Invalid Telegram signature');const authDate=Number(params.get('auth_date'));if(!Number.isFinite(authDate)||authDate>Math.floor(Date.now()/1000)+60||Math.floor(Date.now()/1000)-authDate>3600)throw Error('Expired Telegram login');const user=JSON.parse(params.get('user')||'null');if(!user||!Number.isSafeInteger(user.id))throw Error('Invalid Telegram user');return {id:String(user.id),first_name:String(user.first_name||''),username:String(user.username||'')}}
function auth(req,res,next){try{const header=req.get('Authorization')||'';if(!header.startsWith('tma '))return res.status(401).json({error:'Telegram authorization required'});req.telegramUser=verifyInitData(header.slice(4));next()}catch(e){res.status(401).json({error:'Invalid or expired Telegram authorization'})}}
app.get('/health',(_req,res)=>res.json({ok:true,service:'shakha-donat-api'}));
app.get('/api/me',auth,(req,res)=>res.json({user:req.telegramUser,isAdmin:req.telegramUser.id===ADMIN_ID}));
app.get('/api/admin/check',auth,(req,res)=>req.telegramUser.id===ADMIN_ID?res.json({authorized:true}):res.status(403).json({error:'Forbidden'}));

const database = process.env.DATABASE_URL ? new pg.Pool({
  connectionString: process.env.DATABASE_URL, max: 5, connectionTimeoutMillis: 5000
}) : null;
let schema;
const products = new Map(Object.entries({"PUBG Mobile":["60 UC","325 UC","660 UC","1800 UC"],"Free Fire":["100 алмазов","310 алмазов","520 алмазов"],"Roblox":["400 Robux","800 Robux","1700 Robux"],"Telegram Stars":["50 Stars","100 Stars","500 Stars"],"Telegram Premium":["3 месяца","6 месяцев","12 месяцев"],"Steam":["Указать сумму"],"Mobile Legends":["86 алмазов","172 алмаза","257 алмазов"],"Genshin Impact":["60 кристаллов","330 кристаллов","Благословение Луны"]}));
const fields = 'id, product, package, account, amount, status, price_minor, payment_reference, created_at';
const adminOnly = (req, res, next) => {
  if (req.telegramUser.id !== ADMIN_ID) return res.status(403).json({error:'Доступ только для администратора'});
  next();
};
function orderRoute(handler) {
  return async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (!database) return res.status(503).json({error:'Хранилище заказов ещё не подключено'});
    try {
      schema ??= database.query(`CREATE TABLE IF NOT EXISTS storefront_orders (
        id uuid PRIMARY KEY, customer_id text NOT NULL, product text NOT NULL,
        package text NOT NULL, account text NOT NULL, amount numeric(9,2),
        status text NOT NULL DEFAULT 'new', price_minor integer,
        payment_reference text, created_at timestamptz NOT NULL DEFAULT now()
      ); CREATE INDEX IF NOT EXISTS storefront_orders_customer_date ON storefront_orders (customer_id, created_at DESC)`)
        .catch(error => { schema = undefined; throw error; });
      await schema;
      await handler(req, res);
    } catch (error) {
      console.error('Orders storage error:', error.code || error.name);
      res.status(503).json({error:'История временно недоступна. Повтори попытку позже.'});
    }
  };
}
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
app.get('/api/orders', auth, orderRoute(async (req, res) => {
  const {rows} = await database.query('SELECT ' + fields + ' FROM storefront_orders WHERE customer_id=$1 ORDER BY created_at DESC LIMIT 100', [req.telegramUser.id]);
  res.json({orders:rows, paymentDetails:process.env.PAYMENT_DETAILS || ''});
}));
app.post('/api/orders', auth, orderRoute(async (req, res) => {
  const {id, product, pack, account, amount} = req.body || {};
  if (typeof id !== 'string' || !uuid.test(id) || !products.get(product)?.includes(pack) ||
      typeof account !== 'string' || !account.trim() || account.trim().length > 80 ||
      (product === 'Steam' && (typeof amount !== 'number' || amount < 0.01 || amount > 100000))) {
    return res.status(400).json({error:'Проверь товар, пакет, сумму и ID аккаунта'});
  }
  const {rows} = await database.query(
    'INSERT INTO storefront_orders (id, customer_id, product, package, account, amount) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING RETURNING id',
    [id, req.telegramUser.id, product, pack, account.trim(), product === 'Steam' ? amount : null]
  );
  if (!rows.length) {
    const existing = await database.query('SELECT id FROM storefront_orders WHERE id=$1 AND customer_id=$2', [id, req.telegramUser.id]);
    if (!existing.rows.length) return res.status(409).json({error:'Не удалось создать заявку'});
  }
  res.status(rows.length ? 201 : 200).json({id});
}));
app.post('/api/orders/:id/payment', auth, orderRoute(async (req, res) => {
  const reference = req.body?.reference;
  if (!uuid.test(req.params.id) || typeof reference !== 'string' || !reference.trim() || reference.trim().length > 120) {
    return res.status(400).json({error:'Укажи номер банковской операции'});
  }
  if (!process.env.PAYMENT_DETAILS) return res.status(503).json({error:'Реквизиты ещё не настроены'});
  const result = await database.query(
    "UPDATE storefront_orders SET payment_reference=$1, status='review' WHERE id=$2 AND customer_id=$3 AND status='awaiting_payment'",
    [reference.trim(), req.params.id, req.telegramUser.id]
  );
  if (!result.rowCount) return res.status(409).json({error:'Заявка недоступна для подтверждения оплаты'});
  res.json({ok:true});
}));
app.get('/api/admin/orders', auth, adminOnly, orderRoute(async (_req, res) => {
  const {rows} = await database.query('SELECT ' + fields + ', customer_id FROM storefront_orders ORDER BY created_at DESC LIMIT 100');
  res.json({orders:rows});
}));
app.post('/api/admin/orders/:id', auth, adminOnly, orderRoute(async (req, res) => {
  const transitions = {awaiting_payment:['new'], paid:['review'], completed:['paid'], cancelled:['new','awaiting_payment','review'], review_rejected:['review']};
  const {status, priceMinor} = req.body || {};
  const from = Object.hasOwn(transitions, status) ? transitions[status] : null;
  const needsPrice = status === 'awaiting_payment';
  if (!uuid.test(req.params.id) || !from || (needsPrice && (!Number.isInteger(priceMinor) || priceMinor < 1 || priceMinor > 10000000))) {
    return res.status(400).json({error:'Проверь статус и сумму'});
  }
  if (needsPrice && !process.env.PAYMENT_DETAILS) return res.status(503).json({error:'Сначала настрой реквизиты на сервере'});
  const result = await database.query(
    'UPDATE storefront_orders SET status=$1, price_minor=COALESCE($2,price_minor), payment_reference=CASE WHEN $5 THEN NULL ELSE payment_reference END WHERE id=$3 AND status=ANY($4)',
    [status === 'review_rejected' ? 'awaiting_payment' : status, needsPrice ? priceMinor : null, req.params.id, from, status === 'review_rejected']
  );
  if (!result.rowCount) return res.status(409).json({error:'Статус уже изменился или переход недоступен'});
  res.json({ok:true});
}));

app.use('/api',(_req,res)=>res.status(501).json({error:'Orders, payments and OTP are not enabled yet'}));
const port=Number(process.env.PORT)||3000;app.listen(port,'0.0.0.0',()=>console.log('SHAKHA DONAT API listening on '+port));