const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'change-me-in-prod',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 30
  }
}));

const users = [
  { id: 1, username: 'admin', passwordHash: bcrypt.hashSync('admin123', 10) },
  { id: 2, username: 'user',  passwordHash: bcrypt.hashSync('user123',  10) }
];

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS          = 15 * 60 * 1000;
const CAPTCHA_THRESHOLD   = 3;

const accountState = new Map();

function getAccountState(username) {
  if (!accountState.has(username)) {
    accountState.set(username, { failed: 0, lockUntil: 0 });
  }
  return accountState.get(username);
}

function generateCaptcha() {
  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  return { question: `${a} + ${b}`, answer: a + b };
}

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      ipLimited: true,
      message: 'Demasiados intentos desde tu IP. Espera un minuto.'
    });
  }
});

app.post('/login', loginLimiter, async (req, res) => {
  const { username, password, captcha } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Usuario y contraseña requeridos' });
  }

  const state = getAccountState(username);
  const now = Date.now();

  if (state.lockUntil > now) {
    const lockRemaining = Math.ceil((state.lockUntil - now) / 1000);
    return res.status(429).json({
      success: false,
      locked: true,
      lockRemaining,
      message: `Cuenta bloqueada. Intenta de nuevo en ${lockRemaining}s.`
    });
  }

  const captchaRequired = state.failed >= CAPTCHA_THRESHOLD;
  if (captchaRequired) {
    const expected = req.session.captchaAnswer;
    if (expected === undefined || Number(captcha) !== expected) {
      const c = generateCaptcha();
      req.session.captchaAnswer = c.answer;
      return res.status(400).json({
        success: false,
        captchaRequired: true,
        captchaQuestion: c.question,
        failed: state.failed,
        remaining: Math.max(0, MAX_FAILED_ATTEMPTS - state.failed),
        message: 'Resuelve el CAPTCHA para continuar.'
      });
    }
  }

  const user = users.find(u => u.username === username);
  const ok = user ? await bcrypt.compare(password, user.passwordHash) : false;

  if (!ok) {
    state.failed += 1;

    if (state.failed >= MAX_FAILED_ATTEMPTS) {
      state.lockUntil = now + LOCKOUT_MS;
      state.failed = 0;
      console.warn(`[SECURITY] Cuenta "${username}" bloqueada hasta ${new Date(state.lockUntil).toISOString()} (IP ${req.ip})`);
      return res.status(429).json({
        success: false,
        locked: true,
        lockRemaining: Math.ceil(LOCKOUT_MS / 1000),
        message: 'Demasiados intentos fallidos. Cuenta bloqueada 15 minutos.'
      });
    }

    let captchaQuestion = null;
    const nowNeedsCaptcha = state.failed >= CAPTCHA_THRESHOLD;
    if (nowNeedsCaptcha) {
      const c = generateCaptcha();
      req.session.captchaAnswer = c.answer;
      captchaQuestion = c.question;
    }

    console.warn(`[SECURITY] Login fallido "${username}" (${state.failed}/${MAX_FAILED_ATTEMPTS}) desde IP ${req.ip}`);

    return res.status(401).json({
      success: false,
      failed: state.failed,
      remaining: MAX_FAILED_ATTEMPTS - state.failed,
      captchaRequired: nowNeedsCaptcha,
      captchaQuestion,
      message: 'Credenciales incorrectas'
    });
  }

  state.failed = 0;
  state.lockUntil = 0;
  delete req.session.captchaAnswer;

  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ success: false, message: 'Error de sesión' });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ success: true, message: 'Login exitoso' });
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'No autenticado' });
  }
  res.json({ message: 'Bienvenido ' + req.session.username });
});

app.listen(PORT, () => {
  console.log(`Mitigated server running on port ${PORT}`);
});
