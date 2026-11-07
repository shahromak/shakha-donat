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
const defaultJson = express.json({limit:'20kb'});
const receiptJson = express.json({limit:'4.2mb'});
const settingsJson = express.json({limit:'240kb'});
app.use((req,res,next) => {
  if (req.method === 'POST' && /^\/api\/orders\/[^/]+\/payment$/.test(req.path)) return receiptJson(req,res,next);
  const parser = req.method === 'POST' && req.path === '/api/admin/settings' ? settingsJson : defaultJson;
  parser(req,res,next);
});
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
const products = new Map(Object.entries({
  "PUBG Mobile": [
    "60 UC",
    "325 UC",
    "660 UC",
    "1800 UC"
  ],
  "Free Fire": [
    "100 алмазов",
    "310 алмазов",
    "520 алмазов"
  ],
  "Roblox": [
    "400 Robux",
    "800 Robux",
    "1700 Robux"
  ],
  "Telegram Stars": [
    "50 Stars",
    "100 Stars",
    "250 Stars",
    "500 Stars",
    "1000 Stars",
    "2500 Stars"
  ],
  "Telegram Premium": [
    "3 месяца",
    "6 месяцев",
    "12 месяцев"
  ],
  "Steam": [
    "Указать сумму"
  ],
  "Mobile Legends": ["68 алмазов","135 алмазов","160 алмазов","225 алмазов","265 алмазов","275 алмазов","325 алмазов","390 алмазов","650 алмазов","970 алмазов","1290 алмазов","1775 алмазов","2600 алмазов","6400 алмазов","86 алмазов","172 алмаза","257 алмазов"],
  "Genshin Impact": [
    "60 кристаллов",
    "330 кристаллов",
    "Благословение Луны"
  ]
}));
const paymentMethods = new Set(["alif","dc","other"]);
const fields = 'id, product, package, account, amount, status, price_minor, payment_reference, payment_method, stars_amount, created_at';
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
      ); ALTER TABLE storefront_orders ADD COLUMN IF NOT EXISTS payment_method text; ALTER TABLE storefront_orders ADD COLUMN IF NOT EXISTS payment_details_snapshot text; ALTER TABLE storefront_orders ADD COLUMN IF NOT EXISTS stars_amount integer, ADD COLUMN IF NOT EXISTS telegram_charge_id text, ADD COLUMN IF NOT EXISTS stars_precheckout_id text; CREATE UNIQUE INDEX IF NOT EXISTS storefront_stars_charge ON storefront_orders(telegram_charge_id);
      CREATE TABLE IF NOT EXISTS storefront_receipts (order_id uuid PRIMARY KEY REFERENCES storefront_orders(id),
        mime text NOT NULL, content bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
      ALTER TABLE storefront_receipts ADD COLUMN IF NOT EXISTS decision_token uuid;
      CREATE UNIQUE INDEX IF NOT EXISTS storefront_receipt_decision ON storefront_receipts(decision_token); CREATE TABLE IF NOT EXISTS storefront_settings (id integer PRIMARY KEY, data jsonb NOT NULL); CREATE TABLE IF NOT EXISTS storefront_support (
        id bigserial PRIMARY KEY, customer_id text NOT NULL, sender text NOT NULL,
        body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
      ); CREATE INDEX IF NOT EXISTS storefront_support_customer_id ON storefront_support (customer_id,id);
      CREATE TABLE IF NOT EXISTS storefront_operator_presence (id integer PRIMARY KEY, seen_at timestamptz NOT NULL);
      CREATE INDEX IF NOT EXISTS storefront_orders_customer_date ON storefront_orders (customer_id, created_at DESC); CREATE TABLE IF NOT EXISTS storefront_catalog_migrations (name text PRIMARY KEY);
      WITH first_run AS (
        INSERT INTO storefront_catalog_migrations(name) VALUES ('ml-tjs-2026-11-08') ON CONFLICT DO NOTHING RETURNING name
      )
      INSERT INTO storefront_settings(id,data)
        SELECT 1, '{"prices":{"Mobile Legends":{"68 алмазов":1368,"135 алмазов":2728,"160 алмазов":3090,"225 алмазов":4679,"265 алмазов":5248,"275 алмазов":5478,"325 алмазов":6338,"390 алмазов":5961,"650 алмазов":12615,"970 алмазов":18544,"1290 алмазов":24722,"1775 алмазов":33332,"2600 алмазов":50454,"6400 алмазов":131132}},"payments":{},"banner":""}'::jsonb FROM first_run
      ON CONFLICT (id) DO UPDATE SET data=jsonb_set(storefront_settings.data,'{prices}',
        COALESCE(storefront_settings.data->'prices','{}'::jsonb) || jsonb_build_object('Mobile Legends',
          COALESCE(storefront_settings.data->'prices'->'Mobile Legends','{}'::jsonb) || EXCLUDED.data->'prices'->'Mobile Legends'))`)
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
async function shopSettings() {
  const {rows} = await database.query('SELECT data FROM storefront_settings WHERE id=1');
  return rows[0]?.data || {prices:{}, payments:{}, banner:''};
}
function paymentInstructions(settings, method) {
  return method ? (settings.payments?.[method] || '').trim() : (process.env.PAYMENT_DETAILS || '').trim();
}

const supportOfflineReply = 'Сообщение получено. Сейчас оператор не в сети. Ответим здесь, как только сможем.';
async function supportMessages(customer, connection = database) {
  const {rows} = await connection.query(
    'SELECT id, sender, body, created_at FROM storefront_support WHERE customer_id=$1 ORDER BY id DESC LIMIT 100',
    [customer]
  );
  return rows.reverse();
}
async function operatorOnline(connection = database) {
  const {rows} = await connection.query("SELECT 1 FROM storefront_operator_presence WHERE id=1 AND seen_at > now() - interval '45 seconds'");
  return rows.length > 0;
}
const supportBody = req => typeof req.body?.message === 'string' ? req.body.message.trim() : '';
app.get('/api/support', auth, orderRoute(async (req, res) => {
  res.json({messages:await supportMessages(req.telegramUser.id), online:await operatorOnline()});
}));
app.post('/api/support', auth, orderRoute(async (req, res) => {
  const message = supportBody(req);
  if (!message || message.length > 1500) return res.status(400).json({error:'Введи сообщение до 1500 символов'});
  const customer = req.telegramUser.id;
  const client = await database.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', ['support:' + customer]);
    const online = await operatorOnline(client);
    const {rows} = await client.query(
      "SELECT sender FROM storefront_support WHERE customer_id=$1 AND sender IN ('operator','auto') ORDER BY id DESC LIMIT 1", [customer]
    );
    await client.query("INSERT INTO storefront_support (customer_id,sender,body) VALUES ($1,'customer',$2)", [customer,message]);
    if (!online && rows[0]?.sender !== 'auto') {
      await client.query("INSERT INTO storefront_support (customer_id,sender,body) VALUES ($1,'auto',$2)", [customer,supportOfflineReply]);
    }
    await client.query('COMMIT');
    res.status(201).json({ok:true});
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {client.release();}
}));
app.get('/api/admin/support', auth, adminOnly, orderRoute(async (_req, res) => {
  await database.query('INSERT INTO storefront_operator_presence (id,seen_at) VALUES (1,now()) ON CONFLICT (id) DO UPDATE SET seen_at=now()');
  const {rows} = await database.query(`SELECT DISTINCT ON (customer_id) customer_id, sender, body, created_at, id
    FROM storefront_support WHERE sender <> 'auto' ORDER BY customer_id, id DESC`);
  rows.sort((a,b) => Number(b.id) - Number(a.id));
  res.json({threads:rows.slice(0,100)});
}));
app.get('/api/admin/support/:customer', auth, adminOnly, orderRoute(async (req, res) => {
  if (!/^\d{1,20}$/.test(req.params.customer)) return res.sendStatus(400);
  res.json({messages:await supportMessages(req.params.customer)});
}));
app.post('/api/admin/support/:customer', auth, adminOnly, orderRoute(async (req, res) => {
  const message = supportBody(req);
  const customer = req.params.customer;
  if (!/^\d{1,20}$/.test(customer) || !message || message.length > 1500) return res.status(400).json({error:'Проверь сообщение'});
  const result = await database.query(`INSERT INTO storefront_support (customer_id,sender,body)
    SELECT $1,'operator',$2 WHERE EXISTS (SELECT 1 FROM storefront_support WHERE customer_id=$1 AND sender='customer')`, [customer,message]);
  if (!result.rowCount) return res.sendStatus(404);
  res.status(201).json({ok:true});
}));
app.get('/api/shop/settings', orderRoute(async (_req, res) => {
  const settings = await shopSettings();
  const {prices, banner, bannerImage = '', starsPrices = {}} = settings;
  const availablePayments = [...paymentMethods].filter(method => paymentInstructions(settings, method));
  res.json({prices, starsPrices, banner, bannerImage, availablePayments});
}));
app.get('/api/admin/settings', auth, adminOnly, orderRoute(async (_req, res) => {
  res.json({settings:await shopSettings(), catalog:Object.fromEntries(products), methods:[...paymentMethods]});
}));
app.post('/api/admin/settings', auth, adminOnly, orderRoute(async (req, res) => {
  const {prices, payments, banner, bannerImage = '', starsPrices} = req.body || {};
  const validImage = typeof bannerImage === 'string' && bannerImage.length <= 200000 &&
    (!bannerImage || /^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(bannerImage));
  const record = value => value && typeof value === 'object' && !Array.isArray(value);
  const validPrices = record(prices) && Object.entries(prices).every(([product, packs]) =>
    products.has(product) && product !== 'Steam' && record(packs) && Object.entries(packs).every(([pack, minor]) =>
      products.get(product).includes(pack) && Number.isInteger(minor) && minor > 0 && minor <= 10000000));
  const validPayments = record(payments) && Object.entries(payments).every(([method, value]) =>
    paymentMethods.has(method) && typeof value === 'string' && value.length <= 1200);
  const stars = starsPrices ?? (await shopSettings()).starsPrices ?? {};
  const validStars = record(stars) && Object.entries(stars).every(([product,packs]) =>
    products.has(product) && product !== 'Steam' && record(packs) && Object.entries(packs).every(([pack, amount]) =>
      products.get(product).includes(pack) && Number.isInteger(amount) && amount >= 1 && amount <= 10000));
  if (!validStars || !validPrices || !validPayments || !validImage || typeof banner !== 'string' || banner.length > 300) {
    return res.status(400).json({error:'Проверь цены, реквизиты и текст баннера'});
  }
  await database.query(
    'INSERT INTO storefront_settings (id,data) VALUES (1,$1::jsonb) ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data',
    [JSON.stringify({prices,payments,banner:banner.trim(),bannerImage,starsPrices:stars})]
  );
  res.json({ok:true});
}));
app.get('/api/orders', auth, orderRoute(async (req, res) => {
  const {rows} = await database.query('SELECT ' + fields + ', payment_details_snapshot FROM storefront_orders WHERE customer_id=$1 ORDER BY created_at DESC LIMIT 100', [req.telegramUser.id]);
  const settings = await shopSettings();
  res.json({orders:rows.map(({payment_details_snapshot, ...order}) => ({
    ...order, paymentDetails:order.status === 'awaiting_payment' ? (payment_details_snapshot || paymentInstructions(settings, order.payment_method)) : ''
  }))});
}));
function checkoutPrice(settings, product, pack) {
  const price = settings.prices?.[product]?.[pack];
  return Number.isInteger(price) && price > 0 ? price : null;
}
app.post('/api/orders/stars', auth, orderRoute(async (req,res) => {
  const {id,product,pack,account,confirmedStars} = req.body || {};
  if (!BOT_TOKEN) return res.status(503).json({error:'Оплата Stars пока недоступна'});
  if (typeof id !== 'string' || !uuid.test(id) || !products.get(product)?.includes(pack) ||
      typeof account !== 'string' || !account.trim() || account.trim().length > 80) {
    return res.status(400).json({error:'Проверь пакет и получателя'});
  }
  const settings = await shopSettings();
  const amount = settings.starsPrices?.[product]?.[pack];
  if (!Number.isInteger(amount) || amount < 1 || amount !== confirmedStars) {
    return res.status(409).json({error:'Цена Stars изменилась или ещё не настроена. Открой товар заново.'});
  }
  await database.query(
    "INSERT INTO storefront_orders (id,customer_id,product,package,account,status,payment_method,stars_amount) VALUES ($1,$2,$3,$4,$5,'awaiting_payment','stars',$6) ON CONFLICT (id) DO NOTHING",
    [id,req.telegramUser.id,product,pack,account.trim(),amount]
  );
  const {rows} = await database.query(
    "SELECT id FROM storefront_orders WHERE id=$1 AND customer_id=$2 AND product=$3 AND package=$4 AND account=$5 AND stars_amount=$6 AND status='awaiting_payment'",
    [id,req.telegramUser.id,product,pack,account.trim(),amount]
  );
  if (!rows.length) return res.status(409).json({error:'Счёт уже обработан или данные заказа изменились'});
  const invoice = await telegramCall('createInvoiceLink', {
    title:(product + ' · ' + pack).slice(0,32),description:'Заказ SHAKHA DONAT. Получатель: ' + account.trim(),
    payload:'sdx:' + id,provider_token:'',currency:'XTR',prices:[{label:'Оплата заказа',amount}]
  });
  res.json({id,invoice});
}));
app.post('/api/orders/quote', auth, orderRoute(async (req,res) => {
  const {product, pack, paymentMethod} = req.body || {};
  if (!products.get(product)?.includes(pack) || !paymentMethods.has(paymentMethod)) {
    return res.status(400).json({error:'Проверь пакет и способ оплаты'});
  }
  const settings = await shopSettings();
  const priceMinor = checkoutPrice(settings, product, pack);
  if (!priceMinor) return res.status(409).json({error:'Цена этого пакета ещё не задана. Напиши в поддержку.'});
  if (!paymentInstructions(settings, paymentMethod)) return res.status(409).json({error:'Для выбранного банка ещё нет реквизитов'});
  res.json({priceMinor});
}));
app.post('/api/orders', auth, orderRoute(async (req, res) => {
  const {id, product, pack, account, amount, paymentMethod = null, confirmedPriceMinor = null} = req.body || {};
  if (typeof id !== 'string' || !uuid.test(id) || !products.get(product)?.includes(pack) ||
      (paymentMethod !== null && !paymentMethods.has(paymentMethod)) ||
      typeof account !== 'string' || !account.trim() || account.trim().length > 80 ||
      (product === 'Steam' && (typeof amount !== 'number' || amount < 0.01 || amount > 100000))) {
    return res.status(400).json({error:'Проверь товар, пакет, сумму и ID аккаунта'});
  }
  let priceMinor = null;
  let snapshot = null;
  if (confirmedPriceMinor !== null) {
    const existing = await database.query('SELECT id FROM storefront_orders WHERE id=$1 AND customer_id=$2', [id, req.telegramUser.id]);
    if (existing.rowCount) return res.json({id});
    const settings = await shopSettings();
    priceMinor = checkoutPrice(settings, product, pack);
    snapshot = paymentInstructions(settings, paymentMethod);
    if (!priceMinor || priceMinor !== confirmedPriceMinor || !paymentMethods.has(paymentMethod) || !snapshot) {
      return res.status(409).json({error:'Цена или реквизиты изменились. Открой оформление заново.'});
    }
  }
  const {rows} = await database.query(
    'INSERT INTO storefront_orders (id, customer_id, product, package, account, amount, payment_method, status, price_minor, payment_details_snapshot) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING RETURNING id',
    [id, req.telegramUser.id, product, pack, account.trim(), product === 'Steam' ? amount : null, paymentMethod, priceMinor ? 'awaiting_payment' : 'new', priceMinor, snapshot]
  );
  if (!rows.length) {
    const existing = await database.query('SELECT id FROM storefront_orders WHERE id=$1 AND customer_id=$2', [id, req.telegramUser.id]);
    if (!existing.rows.length) return res.status(409).json({error:'Не удалось создать заявку'});
  }
  res.status(rows.length ? 201 : 200).json({id});
  if (rows.length && BOT_TOKEN) {
    const lines = [
      '✅ Заявка принята',
      '',
      'Код заказа: ' + id,
      'Товар: ' + product,
      'Пакет: ' + (product === 'Steam' ? amount + ' TJS' : pack),
      priceMinor ? 'Статус: ожидает оплаты' : 'Статус: новая заявка',
      '',
      'Проверить статус можно в разделе «Заказы».'
    ];
    void telegramCall('sendMessage', {
      chat_id:req.telegramUser.id,
      text:lines.join('\n'),
      reply_markup:{inline_keyboard:[[{text:'Открыть магазин', web_app:{url:shopUrl}}]]}
    }).catch(() => console.warn('SHAKHA DONAT: order notification was not delivered'));
  }
}));
app.post('/api/orders/:id/method', auth, orderRoute(async (req,res) => {
  const method = req.body?.paymentMethod;
  if (!uuid.test(req.params.id) || !paymentMethods.has(method)) return res.status(400).json({error:'Выбери доступный способ оплаты'});
  const details = paymentInstructions(await shopSettings(), method);
  if (!details) return res.status(409).json({error:'Для этого банка ещё нет реквизитов'});
  const result = await database.query(
    "UPDATE storefront_orders SET payment_method=$1, payment_details_snapshot=CASE WHEN status='awaiting_payment' THEN $2 ELSE NULL END WHERE id=$3 AND customer_id=$4 AND status IN ('new','awaiting_payment') AND stars_amount IS NULL",
    [method,details,req.params.id,req.telegramUser.id]
  );
  if (!result.rowCount) return res.status(409).json({error:'Способ оплаты уже нельзя изменить'});
  res.json({ok:true});
}));
function decodeReceipt(value) {
  if (typeof value !== 'string' || value.length > 4194304 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const content = Buffer.from(value, 'base64');
  if (content.toString('base64') !== value || content.length > 3145728) return null;
  if (content.subarray(0,5).toString() === '%PDF-') return {content,mime:'application/pdf'};
  if (content.subarray(0,8).toString('hex') === '89504e470d0a1a0a') return {content,mime:'image/png'};
  if (content.subarray(0,3).toString('hex') === 'ffd8ff') return {content,mime:'image/jpeg'};
  return null;
}
app.post('/api/orders/:id/payment', auth, orderRoute(async (req, res) => {
  const receipt = decodeReceipt(req.body?.receipt);
  if (!uuid.test(req.params.id) || !receipt) return res.status(400).json({error:'Загрузи чек JPG, PNG или PDF до 3 МБ'});
  const decisionToken = crypto.randomUUID();
  const result = await database.query(`WITH changed AS (
    UPDATE storefront_orders SET status='review', payment_reference=NULL
    WHERE id=$1 AND customer_id=$2 AND status='awaiting_payment' AND price_minor > 0
      AND payment_details_snapshot <> '' AND payment_method IS NOT DISTINCT FROM $5
    RETURNING id,product,package,account,amount,price_minor,payment_method
  ), saved AS (
    INSERT INTO storefront_receipts (order_id,mime,content,decision_token) SELECT id,$3,$4,$6 FROM changed
    ON CONFLICT (order_id) DO UPDATE SET mime=EXCLUDED.mime,content=EXCLUDED.content,decision_token=EXCLUDED.decision_token,created_at=now()
  ) SELECT * FROM changed`, [req.params.id,req.telegramUser.id,receipt.mime,receipt.content,req.body?.paymentMethod ?? null,decisionToken]);
  const order = result.rows[0];
  if (!order) return res.status(409).json({error:'Заказ уже отправлен на проверку или способ оплаты изменился. Обнови историю.'});
  res.json({ok:true});
  if (BOT_TOKEN) void notifyReceipt(order, decisionToken).catch(() => console.warn('SHAKHA DONAT: receipt notification not delivered'));
}));
app.get('/api/admin/orders/:id/receipt', auth, adminOnly, orderRoute(async (req,res) => {
  if (!uuid.test(req.params.id)) return res.sendStatus(400);
  const {rows} = await database.query('SELECT mime,content FROM storefront_receipts WHERE order_id=$1', [req.params.id]);
  if (!rows[0]) return res.sendStatus(404);
  res.json({mime:rows[0].mime,receipt:rows[0].content.toString('base64')});
}));
app.get('/api/admin/orders', auth, adminOnly, orderRoute(async (_req, res) => {
  const {rows} = await database.query('SELECT ' + fields + ', customer_id, EXISTS (SELECT 1 FROM storefront_receipts r WHERE r.order_id=storefront_orders.id) AS has_receipt FROM storefront_orders ORDER BY created_at DESC LIMIT 100');
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
  let paymentSnapshot = null;
  let paymentMethod = null;
  if (needsPrice) {
    const {rows} = await database.query('SELECT payment_method FROM storefront_orders WHERE id=$1', [req.params.id]);
    paymentMethod = rows[0]?.payment_method ?? null;
    paymentSnapshot = paymentInstructions(await shopSettings(), paymentMethod);
    if (!paymentSnapshot) {
      return res.status(503).json({error:'Сначала добавь реквизиты для выбранного способа оплаты'});
    }
  }
  const result = await database.query(
    'UPDATE storefront_orders SET status=$1, price_minor=COALESCE($2,price_minor), payment_reference=CASE WHEN $5 THEN NULL ELSE payment_reference END, payment_details_snapshot=COALESCE($6,payment_details_snapshot) WHERE id=$3 AND status=ANY($4) AND (NOT $7::boolean OR payment_method IS NOT DISTINCT FROM $8) AND (stars_precheckout_id IS NULL OR status<>\'awaiting_payment\')',
    [status === 'review_rejected' ? 'awaiting_payment' : status, needsPrice ? priceMinor : null, req.params.id, from, status === 'review_rejected', paymentSnapshot, needsPrice, paymentMethod]
  );
  if (!result.rowCount) return res.status(409).json({error:'Статус уже изменился или переход недоступен'});
  res.json({ok:true});
}));

app.use('/api',(_req,res)=>res.status(501).json({error:'Orders, payments and OTP are not enabled yet'}));

const botOrigin = 'https://shakha-donat-api-v2.onrender.com';
const shopUrl = 'https://shahromak.github.io/shakha-donat/?v=ml-prices';
const webhookPath = '/telegram/webhook';
const webhookSecret = BOT_TOKEN
  ? crypto.createHmac('sha256', BOT_TOKEN).update('shakha-donat-webhook-v1').digest('hex')
  : '';

async function telegramCall(method, body = {}) {
  const response = await fetch('https://api.telegram.org/bot' + BOT_TOKEN + '/' + method, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body),
    signal:AbortSignal.timeout(8000)
  });
  const result = await response.json();
  if (!response.ok || !result.ok) throw new Error(method + ' HTTP ' + response.status);
  return result.result;
}

async function notifyReceipt(order, decisionToken) {
  await telegramCall('sendMessage', {
    chat_id:ADMIN_ID,
    text:[
      '🧾 Чек на проверку', 'Заказ: ' + order.id,
      'Товар: ' + order.product + ' · ' + (order.amount ? order.amount + ' TJS' : order.package),
      'Получатель: ' + order.account, 'Сумма: ' + (order.price_minor / 100).toFixed(2) + ' TJS'
    ].join('\n'),
    reply_markup:{inline_keyboard:[
      [{text:'Открыть чек в админке',web_app:{url:shopUrl + '#admin'}}],
      [{text:'Подтвердить',callback_data:'pay:yes:' + decisionToken},{text:'Отклонить',callback_data:'pay:no:' + decisionToken}]
    ]}
  });
}
async function handleReceiptDecision(query) {
  const match = /^pay:(yes|no):(.+)$/.exec(query.data || '');
  if (String(query.from?.id) !== ADMIN_ID || !match || !uuid.test(match[2]) || !database) {
    await telegramCall('answerCallbackQuery', {callback_query_id:query.id,text:'Нет доступа или заказ недоступен'});
    return;
  }
  const approved = match[1] === 'yes';
  const {rowCount} = await database.query(
    "UPDATE storefront_orders SET status=$1 WHERE status='review' AND id=(SELECT order_id FROM storefront_receipts WHERE decision_token=$2)",
    [approved ? 'paid' : 'awaiting_payment',match[2]]
  );
  await telegramCall('answerCallbackQuery', {callback_query_id:query.id,text:rowCount ? (approved ? 'Оплата подтверждена' : 'Чек отклонён. Можно загрузить новый.') : 'Заказ уже обработан'});
  if (rowCount && query.message) await telegramCall('editMessageReplyMarkup', {
    chat_id:query.message.chat.id,message_id:query.message.message_id,
    reply_markup:{inline_keyboard:[[{text:'Открыть заказ',web_app:{url:shopUrl + '#admin'}}]]}
  }).catch(() => {});
}
function starsOrderId(payload) {
  return typeof payload === 'string' && payload.startsWith('sdx:') && uuid.test(payload.slice(4)) ? payload.slice(4) : null;
}
async function checkStarsPayment(query) {
  const id = starsOrderId(query.invoice_payload);
  let ok = false;
  if (id && database && query.currency === 'XTR') {
    const result = await database.query(
      "UPDATE storefront_orders SET stars_precheckout_id=$4 WHERE id=$1 AND customer_id=$2 AND stars_amount=$3 AND status='awaiting_payment' AND (stars_precheckout_id IS NULL OR stars_precheckout_id=$4) RETURNING id",
      [id,String(query.from?.id),query.total_amount,query.id]
    );
    ok = result.rowCount === 1;
  }
  await telegramCall('answerPreCheckoutQuery', {
    pre_checkout_query_id:query.id,ok,...(ok ? {} : {error_message:'Счёт недействителен или уже оплачен.'})
  });
}
async function recordStarsPayment(message) {
  const payment = message.successful_payment;
  const id = starsOrderId(payment.invoice_payload);
  if (!id || !database || payment.currency !== 'XTR' || !payment.telegram_payment_charge_id) return;
  await database.query(
    "UPDATE storefront_orders SET status='paid', telegram_charge_id=$1 WHERE id=$2 AND customer_id=$3 AND stars_amount=$4 AND status='awaiting_payment' AND telegram_charge_id IS NULL",
    [payment.telegram_payment_charge_id,id,String(message.from?.id),payment.total_amount]
  );
}
app.post(webhookPath, async (req, res) => {
  const supplied = Buffer.from(req.get('X-Telegram-Bot-Api-Secret-Token') || '');
  const expected = Buffer.from(webhookSecret);
  if (!expected.length || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.sendStatus(403);
  }
  if (req.body?.pre_checkout_query || req.body?.message?.successful_payment) {
    try {
      if (req.body.pre_checkout_query) await checkStarsPayment(req.body.pre_checkout_query);
      else await recordStarsPayment(req.body.message);
      return res.sendStatus(200);
    } catch {
      console.warn('SHAKHA DONAT: Stars payment update failed');
      return res.sendStatus(503);
    }
  }
  if (req.body?.callback_query) {
    try { await handleReceiptDecision(req.body.callback_query); }
    catch { console.warn('SHAKHA DONAT: receipt decision failed'); }
    return res.sendStatus(200);
  }
  const message = req.body?.message;
  if (message?.chat?.type !== 'private' || typeof message.text !== 'string') return res.sendStatus(200);
  const command = message.text.trim().split(/\s+/)[0].toLowerCase().split('@')[0];
  const isAdmin = String(message.from?.id) === ADMIN_ID;
  const buttons = [[{text:'Открыть магазин', web_app:{url:shopUrl}}]];
  if (isAdmin) {
    buttons.push([{text:'Панель администратора', web_app:{url:shopUrl + '#admin'}}]);
    buttons.push([{text:'Настройки магазина', web_app:{url:shopUrl + '#manage'}}]);
  }
  const reply = command === '/admin'
    ? (isAdmin ? 'Панель администратора SHAKHA DONAT. Здесь можно назначать цену, проверять оплату и управлять заказами.' : 'Эта команда доступна только администратору.')
    : command === '/paysupport'
      ? 'По вопросам оплаты открой магазин → Профиль → Поддержка. Укажи код заказа и опиши проблему.'
      : command === '/help'
    ? 'Открой магазин, выбери товар и отправь заявку. Её статус появится в разделе «Заказы».'
    : command === '/orders'
      ? 'История заявок доступна в разделе «Заказы» внутри магазина.'
      : '⚡ Добро пожаловать в SHAKHA DONAT!\n\nПополняй игры, покупай Telegram Stars и оформляй Telegram Premium в одном магазине.\n\nНажми «Открыть магазин», выбери товар и оформи заявку. Статус можно посмотреть в разделе «Заказы».';
  try {
    await telegramCall('sendMessage', {
      chat_id:message.chat.id, text:reply,
      reply_markup:{inline_keyboard:buttons}
    });
    return res.sendStatus(200);
  } catch {
    console.warn('SHAKHA DONAT: could not deliver Telegram reply');
    return res.sendStatus(502);
  }
});

async function connectTelegramBot() {
  if (process.env.RENDER_EXTERNAL_URL !== botOrigin) return;
  if (!BOT_TOKEN) {
    console.warn('SHAKHA DONAT: Telegram bot token is not configured');
    return;
  }
  try {
    const me = await telegramCall('getMe');
    if (me.username?.toLowerCase() !== 'shakhadonatbot') {
      console.warn('SHAKHA DONAT: configured Telegram token belongs to a different bot');
      return;
    }
    await telegramCall('setWebhook', {
      url:botOrigin + webhookPath, secret_token:webhookSecret,
      allowed_updates:['message','callback_query','pre_checkout_query']
    });
    console.log('SHAKHA DONAT: Telegram webhook registered');
  } catch (error) {
    const detail = /^(getMe|setWebhook) HTTP \d{3}$/.test(error.message) ? error.message : error.name;
    console.warn('SHAKHA DONAT: Telegram webhook registration failed:', detail);
  }
}

const port=Number(process.env.PORT)||3000;app.listen(port,'0.0.0.0',()=>{
  console.log('SHAKHA DONAT API listening on '+port);
  void connectTelegramBot();
});