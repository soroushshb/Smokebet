require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, {recursive:true});
const db = new Database(path.join(DATA_DIR, "smokebet.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 phone TEXT NOT NULL,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 points INTEGER NOT NULL DEFAULT 120,
 is_admin INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS matches (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sport TEXT NOT NULL,
 competition TEXT NOT NULL,
 home_team TEXT NOT NULL,
 away_team TEXT NOT NULL,
 starts_at TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS predictions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 match_id INTEGER NOT NULL,
 selection TEXT NOT NULL,
 points_staked INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(user_id, match_id),
 FOREIGN KEY(user_id) REFERENCES users(id),
 FOREIGN KEY(match_id) REFERENCES matches(id)
);
`);
const count = db.prepare("SELECT COUNT(*) n FROM matches").get().n;
if (!count) {
 const add = db.prepare("INSERT INTO matches(sport,competition,home_team,away_team,starts_at) VALUES(?,?,?,?,?)");
 [
  ["فوتبال","لیگ نمایشی اروپا","تیم آذر","تیم باران","امشب · ۲۰:۳۰"],
  ["فوتبال","جام دوستانه","شاهین","ستاره","فردا · ۱۸:۰۰"],
  ["بسکتبال","لیگ نمایشی بسکتبال","تندر","صاعقه","فردا · ۲۱:۰۰"],
  ["تنیس","مسابقات نمایشی","بازیکن الف","بازیکن ب","شنبه · ۱۶:۰۰"]
 ].forEach(x=>add.run(...x));
}
const adminName = process.env.ADMIN_USERNAME || "admin";
const adminPass = process.env.ADMIN_PASSWORD;
if (adminPass) {
 const existing = db.prepare("SELECT id FROM users WHERE username=?").get(adminName);
 if (!existing) {
  db.prepare("INSERT INTO users(phone,username,password_hash,points,is_admin) VALUES(?,?,?,?,1)")
   .run("مدیر", adminName, bcrypt.hashSync(adminPass, 12), 0);
 }
}
app.disable("x-powered-by");
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"30kb"}));
app.use(express.urlencoded({extended:false,limit:"30kb"}));
app.use(session({
 name:"smokebet.sid",
 secret:process.env.SESSION_SECRET || "development-only-change-this-secret",
 resave:false, saveUninitialized:false,
 store:new SQLiteStore({db:"sessions.sqlite",dir:DATA_DIR}),
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:7*24*60*60*1000}
}));
const authLimiter = rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:true,legacyHeaders:false});
const clean = v => String(v || "").trim();
const safeUser = u => ({id:u.id,username:u.username,phone:u.phone,points:u.points,isAdmin:!!u.is_admin,createdAt:u.created_at});
function currentUser(req){return req.session.userId ? db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId) : null;}
function requireAuth(req,res,next){const u=currentUser(req);if(!u)return res.status(401).json({error:"ابتدا وارد حساب شو."});req.user=u;next();}
function requireAdmin(req,res,next){requireAuth(req,res,()=>{if(!req.user.is_admin)return res.status(403).json({error:"دسترسی مدیر لازم است."});next();});}
async function notifyAdmin(subject, text) {
 const {SMTP_HOST,SMTP_PORT,SMTP_SECURE,SMTP_USER,SMTP_PASS,SMTP_FROM,ADMIN_EMAIL}=process.env;
 if(!SMTP_HOST || !ADMIN_EMAIL) return;
 try {
  const transporter=nodemailer.createTransport({host:SMTP_HOST,port:Number(SMTP_PORT||587),secure:SMTP_SECURE==="true",auth:SMTP_USER?{user:SMTP_USER,pass:SMTP_PASS}:undefined});
  await transporter.sendMail({from:SMTP_FROM||SMTP_USER,to:ADMIN_EMAIL,subject,text});
 } catch(e){console.error("Email notification failed:",e.message);}
}
app.get("/api/health",(req,res)=>res.json({ok:true,product:"SMOKEBET"}));
app.post("/api/register",authLimiter,async(req,res)=>{
 const phone=clean(req.body.phone), username=clean(req.body.username), password=String(req.body.password||"");
 if(!/^[0-9+\-\s()]{7,20}$/.test(phone))return res.status(400).json({error:"شماره تماس معتبر وارد کن."});
 if(!/^[\p{L}\p{N}_.-]{3,24}$/u.test(username))return res.status(400).json({error:"نام کاربری باید ۳ تا ۲۴ نویسه باشد."});
 if(password.length<10 || password.length>72)return res.status(400).json({error:"رمز عبور باید حداقل ۱۰ نویسه داشته باشد."});
 try{
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare("INSERT INTO users(phone,username,password_hash) VALUES(?,?,?)").run(phone,username,hash);
  req.session.userId=info.lastInsertRowid;
  notifyAdmin("ثبت‌نام جدید SMOKEBET",`کاربر جدید ثبت‌نام کرد.\nنام کاربری: ${username}\nشماره تماس: ${phone}\nرمز عبور ارسال نمی‌شود.`);
  res.json({user:safeUser(currentUser(req))});
 }catch(e){res.status(409).json({error:"این نام کاربری قبلاً ثبت شده است."});}
});
app.post("/api/login",authLimiter,async(req,res)=>{
 const username=clean(req.body.username),password=String(req.body.password||"");
 const u=db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").get(username);
 if(!u || !(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"نام کاربری یا رمز عبور اشتباه است."});
 req.session.userId=u.id;res.json({user:safeUser(u)});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",requireAuth,(req,res)=>res.json({user:safeUser(req.user)}));
app.get("/api/matches",(req,res)=>res.json({matches:db.prepare("SELECT * FROM matches ORDER BY id DESC").all()}));
app.get("/api/predictions",requireAuth,(req,res)=>{
 const rows=db.prepare(`SELECT p.*,m.sport,m.competition,m.home_team,m.away_team,m.starts_at
 FROM predictions p JOIN matches m ON m.id=p.match_id WHERE p.user_id=? ORDER BY p.id DESC`).all(req.user.id);
 res.json({predictions:rows});
});
app.post("/api/predictions",requireAuth,(req,res)=>{
 const matchId=Number(req.body.matchId),selection=clean(req.body.selection),stake=Number(req.body.points);
 if(!Number.isInteger(matchId)||!["home","draw","away"].includes(selection)||!Number.isInteger(stake)||stake<1||stake>100000)return res.status(400).json({error:"اطلاعات پیش‌بینی معتبر نیست."});
 const match=db.prepare("SELECT * FROM matches WHERE id=? AND status='open'").get(matchId);
 if(!match)return res.status(404).json({error:"این مسابقه در دسترس نیست."});
 if(req.user.points<stake)return res.status(400).json({error:"امتیاز مجازی کافی نیست."});
 try{
  db.transaction(()=>{
   db.prepare("INSERT INTO predictions(user_id,match_id,selection,points_staked) VALUES(?,?,?,?)").run(req.user.id,matchId,selection,stake);
   db.prepare("UPDATE users SET points=points-? WHERE id=?").run(stake,req.user.id);
  })();
  notifyAdmin("پیش‌بینی جدید SMOKEBET",`کاربر: ${req.user.username}\nمسابقه: ${match.home_team} - ${match.away_team}\nانتخاب: ${selection}\nامتیاز مجازی: ${stake}`);
  res.json({user:safeUser(currentUser(req))});
 }catch(e){res.status(409).json({error:"برای این مسابقه قبلاً پیش‌بینی ثبت کرده‌ای."});}
});
app.get("/api/leaderboard",(req,res)=>res.json({users:db.prepare("SELECT username,points FROM users WHERE is_admin=0 ORDER BY points DESC LIMIT 50").all()}));
app.get("/api/admin/summary",requireAdmin,(req,res)=>{
 const users=db.prepare("SELECT id,phone,username,points,created_at FROM users WHERE is_admin=0 ORDER BY id DESC").all();
 const predictions=db.prepare(`SELECT p.id,p.selection,p.points_staked,p.created_at,u.username,m.home_team,m.away_team
 FROM predictions p JOIN users u ON u.id=p.user_id JOIN matches m ON m.id=p.match_id ORDER BY p.id DESC LIMIT 200`).all();
 res.json({users,predictions});
});
app.post("/api/admin/matches",requireAdmin,(req,res)=>{
 const {sport,competition,homeTeam,awayTeam,startsAt}=req.body;
 if(![sport,competition,homeTeam,awayTeam,startsAt].every(x=>clean(x)))return res.status(400).json({error:"همه فیلدها را تکمیل کن."});
 const info=db.prepare("INSERT INTO matches(sport,competition,home_team,away_team,starts_at) VALUES(?,?,?,?,?)").run(...[sport,competition,homeTeam,awayTeam,startsAt].map(clean));
 res.json({id:info.lastInsertRowid});
});
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`SMOKEBET running at http://localhost:${PORT}`));
