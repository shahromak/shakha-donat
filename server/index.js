import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
const app=express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({limit:'20kb'}));
app.use('/api',rateLimit({windowMs:15*60*1000,limit:90,standardHeaders:'draft-7',legacyHeaders:false}));
const BOT_TOKEN=process.env.TELEGRAM_BOT_TOKEN||'';
const ADMIN_ID=String(process.env.ADMIN_TELEGRAM_ID||'8465117749');
const allowedOrigins=(process.env.ALLOWED_ORIGINS||'https://shahromak.github.io').split(',').map(s=>s.trim());
app.use((req,res,next)=>{const origin=req.headers.origin;if(origin&&allowedOrigins.includes(origin)){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');res.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');}if(req.method==='OPTIONS')return res.sendStatus(204);next()});
function verifyInitData(raw){if(!BOT_TOKEN||typeof raw!=='string'||raw.length>8192)throw Error('Telegram authentication unavailable');const params=new URLSearchParams(raw),hash=params.get('hash');if(!hash||!/^[0-9a-f]{64}$/i.test(hash))throw Error('Invalid Telegram signature');params.delete('hash');const check=[...params.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>k+'='+v).join('\n');const secret=crypto.createHmac('sha256','WebAppData').update(BOT_TOKEN).digest();const digest=crypto.createHmac('sha256',secret).update(check).digest();if(!crypto.timingSafeEqual(Buffer.from(hash,'hex'),digest))throw Error('Invalid Telegram signature');const authDate=Number(params.get('auth_date'));if(!Number.isFinite(authDate)||authDate>Math.floor(Date.now()/1000)+60||Math.floor(Date.now()/1000)-authDate>3600)throw Error('Expired Telegram login');const user=JSON.parse(params.get('user')||'null');if(!user||!Number.isSafeInteger(user.id))throw Error('Invalid Telegram user');return {id:String(user.id),first_name:String(user.first_name||''),username:String(user.username||'')}}
function auth(req,res,next){try{const header=req.get('Authorization')||'';if(!header.startsWith('tma '))return res.status(401).json({error:'Telegram authorization required'});req.telegramUser=verifyInitData(header.slice(4));next()}catch(e){res.status(401).json({error:'Invalid or expired Telegram authorization'})}}
app.get('/health',(_req,res)=>res.json({ok:true,service:'shakha-donat-api'}));
app.get('/api/me',auth,(req,res)=>res.json({user:req.telegramUser,isAdmin:req.telegramUser.id===ADMIN_ID}));
app.get('/api/admin/check',auth,(req,res)=>req.telegramUser.id===ADMIN_ID?res.json({authorized:true}):res.status(403).json({error:'Forbidden'}));
app.use('/api',(_req,res)=>res.status(501).json({error:'Orders, payments and OTP are not enabled yet'}));
const port=Number(process.env.PORT)||3000;app.listen(port,'0.0.0.0',()=>console.log('SHAKHA DONAT API listening on '+port));