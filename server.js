require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const required = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'SESSION_SECRET'];
for (const key of required) if (!process.env[key]) {
  console.error(`Missing required environment variable: ${key}`);
  process.exit(1);
}
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
});
const app = express();
const PORT = Number(process.env.PORT || 3000);
const clean = v => String(v ?? '').trim();
const safeUser = u => ({ id: u.id, username: u.username, phone: u.phone, points: u.points, isAdmin: !!u.is_admin, createdAt: u.created_at });

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false, limit: '30kb' }));
app.use(session({
  name: 'smokebet.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  // For production with multiple instances, replace MemoryStore with a persistent session store.
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });

async function getUser(id) {
  const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data;
}
async function currentUser(req) { return req.session.userId ? getUser(req.session.userId) : null; }
async function requireAuth(req, res, next) {
  try {
    const u = await currentUser(req);
    if (!u) return res.status(401).json({ error: 'ابتدا وارد حساب شو.' });
    req.user = u; next();
  } catch (e) { next(e); }
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'دسترسی مدیر لازم است.' });
    next();
  });
}

app.get('/api/health', (req, res) => res.json({ ok: true, product: 'SMOKEBET', database: 'supabase' }));

app.post('/api/register', authLimiter, async (req, res, next) => {
  try {
    const phone = clean(req.body.phone), username = clean(req.body.username), password = String(req.body.password || '');
    if (!/^[0-9+\-\s()]{7,20}$/.test(phone)) return res.status(400).json({ error: 'شماره تماس معتبر وارد کن.' });
    if (!/^[\p{L}\p{N}_.-]{3,24}$/u.test(username)) return res.status(400).json({ error: 'نام کاربری باید ۳ تا ۲۴ نویسه باشد.' });
    if (password.length < 10 || password.length > 72) return res.status(400).json({ error: 'رمز عبور باید حداقل ۱۰ نویسه داشته باشد.' });
    const password_hash = await bcrypt.hash(password, 12);
    const { data, error } = await supabase.from('users').insert({ phone, username, password_hash }).select('*').single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'این نام کاربری قبلاً ثبت شده است.' });
      throw error;
    }
    req.session.userId = data.id;
    res.json({ user: safeUser(data) });
  } catch (e) { next(e); }
});

app.post('/api/login', authLimiter, async (req, res, next) => {
  try {
    const username = clean(req.body.username), password = String(req.body.password || '');
    const { data, error } = await supabase.from('users').select('*').ilike('username', username).maybeSingle();
    if (error) throw error;
    if (!data || !(await bcrypt.compare(password, data.password_hash))) return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است.' });
    req.session.userId = data.id;
    res.json({ user: safeUser(data) });
  } catch (e) { next(e); }
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', requireAuth, (req, res) => res.json({ user: safeUser(req.user) }));

app.get('/api/matches', async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('matches').select('*').order('id', { ascending: false });
    if (error) throw error;
    res.json({ matches: data || [] });
  } catch (e) { next(e); }
});
app.get('/api/predictions', requireAuth, async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('predictions')
      .select('id,selection,points_staked,created_at,matches(sport,competition,home_team,away_team,starts_at)')
      .eq('user_id', req.user.id).order('id', { ascending: false });
    if (error) throw error;
    const predictions = (data || []).map(p => ({ ...p, ...(p.matches || {}) }));
    res.json({ predictions });
  } catch (e) { next(e); }
});
app.post('/api/predictions', requireAuth, async (req, res, next) => {
  try {
    const matchId = Number(req.body.matchId), selection = clean(req.body.selection), stake = Number(req.body.points);
    if (!Number.isInteger(matchId) || !['home', 'draw', 'away'].includes(selection) || !Number.isInteger(stake) || stake < 1 || stake > 100000)
      return res.status(400).json({ error: 'اطلاعات پیش‌بینی معتبر نیست.' });
    const { error } = await supabase.rpc('smokebet_place_prediction', {
      p_user_id: req.user.id, p_match_id: matchId, p_selection: selection, p_points: stake
    });
    if (error) {
      if (error.message?.includes('INSUFFICIENT_POINTS')) return res.status(400).json({ error: 'امتیاز مجازی کافی نیست.' });
      if (error.message?.includes('MATCH_NOT_OPEN')) return res.status(404).json({ error: 'این مسابقه در دسترس نیست.' });
      if (error.code === '23505' || error.message?.includes('DUPLICATE_PREDICTION')) return res.status(409).json({ error: 'برای این مسابقه قبلاً پیش‌بینی ثبت کرده‌ای.' });
      throw error;
    }
    res.json({ user: safeUser(await getUser(req.user.id)) });
  } catch (e) { next(e); }
});
app.get('/api/leaderboard', async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('users').select('username,points').eq('is_admin', false).order('points', { ascending: false }).limit(50);
    if (error) throw error;
    res.json({ users: data || [] });
  } catch (e) { next(e); }
});
app.get('/api/admin/summary', requireAdmin, async (req, res, next) => {
  try {
    const [u, p] = await Promise.all([
      supabase.from('users').select('id,phone,username,points,created_at').eq('is_admin', false).order('id', { ascending: false }),
      supabase.from('predictions').select('id,selection,points_staked,created_at,users(username),matches(home_team,away_team)').order('id', { ascending: false }).limit(200)
    ]);
    if (u.error) throw u.error; if (p.error) throw p.error;
    const predictions = (p.data || []).map(x => ({ id: x.id, selection: x.selection, points_staked: x.points_staked, created_at: x.created_at, username: x.users?.username, home_team: x.matches?.home_team, away_team: x.matches?.away_team }));
    res.json({ users: u.data || [], predictions });
  } catch (e) { next(e); }
});
app.post('/api/admin/matches', requireAdmin, async (req, res, next) => {
  try {
    const { sport, competition, homeTeam, awayTeam, startsAt } = req.body;
    if (![sport, competition, homeTeam, awayTeam, startsAt].every(x => clean(x))) return res.status(400).json({ error: 'همه فیلدها را تکمیل کن.' });
    const { data, error } = await supabase.from('matches').insert({ sport: clean(sport), competition: clean(competition), home_team: clean(homeTeam), away_team: clean(awayTeam), starts_at: clean(startsAt) }).select('id').single();
    if (error) throw error;
    res.json({ id: data.id });
  } catch (e) { next(e); }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => {
  console.error('Request failed:', err.message);
  res.status(500).json({ error: 'خطای سرور رخ داد. تنظیمات سرور و دیتابیس را بررسی کن.' });
});

async function start() {
  // Create the initial administrator only when configured and not already present.
  if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
    const { data: existing, error } = await supabase.from('users').select('id').ilike('username', process.env.ADMIN_USERNAME).maybeSingle();
    if (error) throw error;
    if (!existing) {
      const { error: insertError } = await supabase.from('users').insert({
        phone: 'مدیر', username: process.env.ADMIN_USERNAME,
        password_hash: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12), points: 0, is_admin: true
      });
      if (insertError) throw insertError;
    }
  }
  const { count, error } = await supabase.from('matches').select('*', { count: 'exact', head: true });
  if (error) throw error;
  if (!count) {
    const { error: seedError } = await supabase.from('matches').insert([
      { sport: 'فوتبال', competition: 'لیگ نمایشی اروپا', home_team: 'تیم آذر', away_team: 'تیم باران', starts_at: 'امشب · ۲۰:۳۰' },
      { sport: 'فوتبال', competition: 'جام دوستانه', home_team: 'شاهین', away_team: 'ستاره', starts_at: 'فردا · ۱۸:۰۰' },
      { sport: 'بسکتبال', competition: 'لیگ نمایشی بسکتبال', home_team: 'تندر', away_team: 'صاعقه', starts_at: 'فردا · ۲۱:۰۰' },
      { sport: 'تنیس', competition: 'مسابقات نمایشی', home_team: 'بازیکن الف', away_team: 'بازیکن ب', starts_at: 'شنبه · ۱۶:۰۰' }
    ]);
    if (seedError) throw seedError;
  }
  app.listen(PORT, () => console.log(`SMOKEBET listening on ${PORT}`));
}
start().catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
