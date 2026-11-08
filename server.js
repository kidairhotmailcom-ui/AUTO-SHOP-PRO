
'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');

// ==========================================
// 1. ENVIRONMENT CONFIGURATION
// ==========================================

const requiredEnv = [
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'JWT_SECRET'
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`Missing environment variable: ${key}`);
    process.exit(1);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  console.error('JWT_SECRET must be at least 32 characters.');
  process.exit(1);
}

const PORT = Number(process.env.PORT || 3000);
const TOKEN_MINUTES = Number(process.env.SETUP_TOKEN_MINUTES || 20);

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '100kb' }));

// ==========================================
// 2. CORS
// ==========================================

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

const mainCors = cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
});

const publicCors = cors({
  origin: '*',
  methods: ['GET']
});

app.use((req, res, next) =>
  req.path.startsWith('/api/public/')
    ? publicCors(req, res, next)
    : mainCors(req, res, next)
);

// ==========================================
// 3. RATE LIMIT
// ==========================================

app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'มีการเรียกใช้งานมากเกินไป กรุณาลองใหม่ภายหลัง'
  }
});

// ==========================================
// 4. SUPABASE
// ==========================================

const admin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

const publicClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

// ==========================================
// 5. HELPERS
// ==========================================

function clean(value, max = 160) {
  return typeof value === 'string'
    ? value.trim().slice(0, max)
    : '';
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validShopCode(value) {
  return /^[A-Z0-9_-]{4,24}$/.test(value);
}

function makeLicenseKey() {
  const parts = crypto.randomBytes(12)
    .toString('hex')
    .toUpperCase()
    .match(/.{1,4}/g);

  return 'ASP-' + parts.join('-');
}

function makeTemporaryPassword() {
  return crypto.randomBytes(36).toString('base64url') + 'aA1!';
}

function hashIp(ip) {
  return crypto.createHash('sha256')
    .update(String(ip || ''))
    .digest('hex');
}

function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

function num(v, d) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

// แปลงวันที่เป็น YYYY-MM-DD ตาม UTC
function dateString(date) {
  return date.toISOString().slice(0, 10);
}

// บวกเดือนโดยไม่ใช้จำนวนวันคงที่
function addMonths(dateStringValue, months) {
  const [year, month, day] = dateStringValue.split('-').map(Number);

  const targetMonth = month - 1 + months;
  const targetYear = year + Math.floor(targetMonth / 12);
  const normalizedMonth = ((targetMonth % 12) + 12) % 12;

  const lastDay = new Date(
    Date.UTC(targetYear, normalizedMonth + 1, 0)
  ).getUTCDate();

  const finalDay = Math.min(day, lastDay);

  return dateString(
    new Date(Date.UTC(targetYear, normalizedMonth, finalDay))
  );
}

// ==========================================
// 6. EMAIL
// ==========================================

async function sendLicenseEmail({
  to,
  ownerName,
  shopName,
  shopCode,
  licenseKey
}) {
  const gmailUser = String(process.env.GMAIL_USER || '').trim();
  const appPassword = String(
    process.env.GMAIL_APP_PASSWORD || ''
  ).replace(/\s+/g, '');

  if (!gmailUser || !appPassword) {
    const error = new Error('EMAIL_NOT_CONFIGURED');
    error.code = 'EMAIL_NOT_CONFIGURED';
    throw error;
  }

  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: gmailUser,
      pass: appPassword
    },
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 20000
  });

  try {
    return await transporter.sendMail({
      from: {
        name: 'AUTO SHOP PRO',
        address: gmailUser
      },
      to,
      subject: 'License Key สำหรับ AUTO SHOP PRO',
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.7;color:#222">
          <h2>สมัคร AUTO SHOP PRO สำเร็จ</h2>
          <p>สวัสดีคุณ ${escapeHtml(ownerName)}</p>
          <p><strong>ชื่อร้าน:</strong> ${escapeHtml(shopName)}</p>
          <p><strong>Shop Code:</strong> ${escapeHtml(shopCode)}</p>
          <p><strong>License Key:</strong></p>
          <p style="font-size:20px;font-weight:bold">
            ${escapeHtml(licenseKey)}
          </p>
          <p>กรุณาเก็บ License Key นี้ไว้</p>
          <p>AUTO SHOP PRO</p>
        </div>
      `,
      text:
        `สมัคร AUTO SHOP PRO สำเร็จ\n` +
        `ชื่อร้าน: ${shopName}\n` +
        `Shop Code: ${shopCode}\n` +
        `License Key: ${licenseKey}`
    });
  } catch (err) {
    console.error('Gmail SMTP email error:', err.message);
    const error = new Error('EMAIL_SEND_FAILED');
    error.code = 'EMAIL_SEND_FAILED';
    throw error;
  } finally {
    transporter.close();
  }
}

async function notifyOwnerSmtp({
  ownerName,
  shopName,
  shopCode,
  customerEmail
}) {
  const gmailUser = String(process.env.GMAIL_USER || '').trim();
  const appPassword = String(
    process.env.GMAIL_APP_PASSWORD || ''
  ).replace(/\s+/g, '');

  const recipient = String(
    process.env.ALERT_EMAIL || gmailUser
  ).trim();

  if (!gmailUser || !appPassword || !recipient) {
    throw new Error('OWNER_NOTIFICATION_EMAIL_NOT_CONFIGURED');
  }

  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: gmailUser,
      pass: appPassword
    },
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 20000
  });

  try {
    const registeredAt = new Date().toLocaleString(
      'th-TH',
      { timeZone: 'Asia/Bangkok' }
    );

    await transporter.sendMail({
      from: {
        name: 'AUTO SHOP PRO',
        address: gmailUser
      },
      to: recipient,
      subject: 'แจ้งเตือน: มีลูกค้าสมัคร AUTO SHOP PRO ใหม่',
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.8;color:#222">
          <h2>มีลูกค้าสมัคร AUTO SHOP PRO ใหม่</h2>
          <p><strong>เจ้าของร้าน:</strong> ${escapeHtml(ownerName)}</p>
          <p><strong>ร้าน:</strong> ${escapeHtml(shopName)}</p>
          <p><strong>Shop Code:</strong> ${escapeHtml(shopCode)}</p>
          <p><strong>อีเมล:</strong> ${escapeHtml(customerEmail)}</p>
          <p><strong>เวลาสมัคร:</strong> ${registeredAt}</p>
          <p>
            <a href="https://kidairhotmailcom-ui.github.io/AUTO-SHOP-PRO/">
              เปิด AUTO SHOP PRO
            </a>
          </p>
        </div>
      `,
      text:
        'มีลูกค้าสมัคร AUTO SHOP PRO ใหม่\n' +
        `ชื่อร้าน: ${shopName}\n` +
        `ชื่อเจ้าของร้าน: ${ownerName}\n` +
        `Shop Code: ${shopCode}\n` +
        `อีเมลลูกค้า: ${customerEmail}\n` +
        `เวลาสมัคร: ${registeredAt}\n` +
        'https://kidairhotmailcom-ui.github.io/AUTO-SHOP-PRO/'
    });
  } finally {
    transporter.close();
  }
}

async function notifyOwner(info) {
  const hook = String(
    process.env.OWNER_ALERT_WEBHOOK_URL || ''
  ).trim();

  if (!hook) {
    return notifyOwnerSmtp(info);
  }

  const registeredAt = new Date().toLocaleString(
    'th-TH',
    { timeZone: 'Asia/Bangkok' }
  );

  const response = await fetch(hook, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain;charset=utf-8'
    },
    redirect: 'follow',
    signal: AbortSignal.timeout(15000),
    body: JSON.stringify({
      secret: process.env.OWNER_ALERT_SECRET || '',
      subject: 'แจ้งเตือน: มีลูกค้าสมัคร AUTO SHOP PRO ใหม่',
      text:
        'มีลูกค้าสมัคร AUTO SHOP PRO ใหม่\n\n' +
        'ชื่อร้าน: ' + info.shopName + '\n' +
        'ชื่อเจ้าของร้าน: ' + info.ownerName + '\n' +
        'Shop Code: ' + info.shopCode + '\n' +
        'อีเมลลูกค้า: ' + info.customerEmail + '\n' +
        'เวลาสมัคร: ' + registeredAt + '\n\n' +
        'https://kidairhotmailcom-ui.github.io/AUTO-SHOP-PRO/'
    })
  });

  const out = await response.text();

  if (!response.ok || out.trim() !== 'ok') {
    throw new Error('OWNER_WEBHOOK_FAILED');
  }
}

// ==========================================
// 7. AUTH ATTEMPT LOG
// ==========================================

async function recordAttempt(identifier, action, success, req) {
  try {
    const { error } = await admin.from('login_attempts').insert({
      login_identifier: String(identifier || 'unknown').slice(0, 160),
      attempt_type: action,
      success: Boolean(success),
      ip_hash: hashIp(req && req.ip)
    });

    if (error) {
      console.error('recordAttempt error:', error.message);
    }
  } catch (err) {
    console.error('recordAttempt error:', err.message);
  }
}

// ==========================================
// 8. SETUP TOKEN
// ==========================================

function createSetupToken(userId, shopId, licenseId) {
  return jwt.sign(
    {
      sub: userId,
      shop_id: shopId,
      license_id: licenseId,
      purpose: 'owner_setup'
    },
    process.env.JWT_SECRET,
    { expiresIn: `${TOKEN_MINUTES}m` }
  );
}

function requireSetupToken(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : '';

  if (!token) {
    return res.status(401).json({
      error: 'ไม่พบ Setup Token'
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (payload.purpose !== 'owner_setup') {
      return res.status(401).json({
        error: 'Setup Token ไม่ถูกต้อง'
      });
    }

    req.setup = payload;
    return next();
  } catch (err) {
    return res.status(401).json({
      error: 'Setup Token หมดอายุหรือไม่ถูกต้อง'
    });
  }
}

function makeShopCode() {
  return 'SHOP' + crypto.randomBytes(4).toString('hex').toUpperCase();
}

// ==========================================
// 9. SYSTEM ADMIN AUTHENTICATION
// ==========================================

function requireSystemAdmin(req, res, next) {
  const configuredKey = String(
    process.env.ADMIN_API_KEY || ''
  );

  if (configuredKey.length < 32) {
    return res.status(503).json({
      error: 'ระบบหลังบ้านยังไม่ได้ตั้งค่า ADMIN_API_KEY'
    });
  }

  const header = req.headers.authorization || '';
  const suppliedKey = header.startsWith('Bearer ')
    ? header.slice(7)
    : '';

  if (!suppliedKey) {
    return res.status(401).json({
      error: 'ไม่มีสิทธิ์เข้าถึงระบบหลังบ้าน'
    });
  }

  const expected = Buffer.from(configuredKey);
  const received = Buffer.from(suppliedKey);

  if (
    expected.length !== received.length ||
    !crypto.timingSafeEqual(expected, received)
  ) {
    return res.status(403).json({
      error: 'รหัสผู้ดูแลระบบไม่ถูกต้อง'
    });
  }

  return next();
}

// ==========================================
// 10. REGISTER SHOP
// ==========================================

app.post('/api/register', authLimiter, async (req, res) => {
  if (process.env.SIGNUPS_OPEN === 'false') {
    return res.status(403).json({
      error: 'ขณะนี้ปิดรับสมัครชั่วคราว กรุณาติดต่อทีมงาน'
    });
  }

  const shopName = clean(
    req.body.shop_name || req.body.owner_name, 120
  );

  const ownerName = clean(
    req.body.owner_name || req.body.shop_name, 120
  );

  const address = clean(req.body.address, 300);
  const email = clean(req.body.email, 160).toLowerCase();
  const password = typeof req.body.password === 'string'
    ? req.body.password
    : '';

  if (!shopName || !validEmail(email)) {
    return res.status(400).json({
      error: 'กรุณากรอกชื่อร้านและอีเมลให้ถูกต้อง'
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: 'รหัสผ่านต้องมีความยาว 8-128 ตัวอักษร'
    });
  }

  let createdUserId = null;
  let createdLicenseId = null;
  let createdShopId = null;

  try {
    const { data: existing, error: existingError } =
      await admin.from('shops')
        .select('id')
        .eq('email', email)
        .maybeSingle();

    if (existingError) throw existingError;

    if (existing) {
      return res.status(409).json({
        error: 'อีเมลนี้สมัครร้านแล้ว'
      });
    }

    const { data: userData, error: userError } =
      await admin.auth.admin.createUser({
        email,
        password,
        email_confirm: true
      });

    if (userError) throw userError;
    createdUserId = userData.user.id;

    const { data: license, error: licenseError } =
      await admin.from('licenses')
        .insert({
          license_key: makeLicenseKey(),
          status: 'suspended',
          plan: 'trial'
        })
        .select('id')
        .single();

    if (licenseError) throw licenseError;
    createdLicenseId = license.id;

    const { data: shop, error: shopError } =
      await admin.from('shops')
        .insert({
          owner_user_id: createdUserId,
          license_id: createdLicenseId,
          shop_code: makeShopCode(),
          shop_name: shopName,
          owner_name: ownerName,
          address,
          email,
          is_active: false
        })
        .select('id, shop_code, shop_name')
        .single();

    if (shopError) throw shopError;
    createdShopId = shop.id;

    await recordAttempt(email, 'register', true, req);

    notifyOwner({
      ownerName,
      shopName,
      shopCode: shop.shop_code,
      customerEmail: email
    }).catch(error => {
      console.error('Owner notification failed:', error.message);
    });

    return res.status(201).json({
      ok: true,
      pending: true,
      message: 'สมัครร้านสำเร็จ รอเจ้าของระบบอนุมัติ',
      shop: {
        shop_code: shop.shop_code,
        shop_name: shop.shop_name
      }
    });

  } catch (error) {
    console.error('Register error:', {
      message: error.message,
      code: error.code,
      details: error.details,
      hint: error.hint
    });

    try {
      if (createdShopId) {
        await admin.from('shops').delete().eq('id', createdShopId);
      }

      if (createdLicenseId) {
        await admin.from('licenses').delete().eq('id', createdLicenseId);
      }

      if (createdUserId) {
        await admin.auth.admin.deleteUser(createdUserId);
      }
    } catch (rollbackErr) {
      console.error('Register rollback error:', rollbackErr.message);
    }

    await recordAttempt(email || 'unknown', 'register', false, req);

    if (
      error.code === '23505' ||
      error.code === 'email_exists' ||
      error.code === 'user_already_exists' ||
      /already (been )?registered|already exists|duplicate/i.test(error.message || '')
    ) {
      return res.status(409).json({
        error: 'อีเมลนี้สมัครร้านแล้ว'
      });
    }

    return res.status(500).json({
      error: 'สมัครร้านไม่สำเร็จ กรุณาลองใหม่ภายหลัง'
    });
  }
});

// ==========================================
// 11. PUBLIC SIGNUP STATS
// ==========================================

const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'เรียกข้อมูลถี่เกินไป กรุณารอสักครู่'
  }
});

let statsCache = {
  at: 0,
  body: null
};

app.get('/api/public/signup-stats', publicLimiter, async (req, res) => {
  try {
    if (statsCache.body && Date.now() - statsCache.at < 25000) {
      return res.json(statsCache.body);
    }

    const { data, error } = await admin
      .from('shops')
      .select('is_active, opening_started_at, created_at, licenses(starts_at)')
      .eq('is_test', false)
      .limit(10000);

    if (error) throw error;

    const bangkokDay = d =>
      new Date(d.getTime() + 7 * 3600 * 1000)
        .toISOString().slice(0, 10);

    const perDay = {};
    let total = 0;
    let pending = 0;
    let inProgress = 0;
    let activated = 0;

    for (const shop of data) {
      total++;

      const lic = Array.isArray(shop.licenses)
        ? shop.licenses[0]
        : shop.licenses;

      const everApproved = Boolean(lic && lic.starts_at);

      if (shop.is_active) {
        activated++;
      } else if (!everApproved) {
        if (shop.opening_started_at) inProgress++;
        else pending++;
      }

      const key = bangkokDay(new Date(shop.created_at));
      perDay[key] = (perDay[key] || 0) + 1;
    }

    const series = [];

    for (let i = 13; i >= 0; i--) {
      const key = bangkokDay(
        new Date(Date.now() - i * 86400000)
      );

      series.push({
        date: key,
        count: perDay[key] || 0
      });
    }

    const body = {
      total,
      pending,
      in_progress: inProgress,
      activated,
      accepting: process.env.SIGNUPS_OPEN !== 'false',
      daily: series,
      updated_at: new Date().toISOString()
    };

    statsCache = {
      at: Date.now(),
      body
    };

    return res.json(body);

  } catch (error) {
    console.error('Public stats error:', error.message);

    return res.status(503).json({
      error: 'ยังไม่สามารถโหลดข้อมูลได้'
    });
  }
});

// ==========================================
// 12. DELIVERY QUOTE
// ==========================================

const quoteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'เรียกคำนวณเส้นทางถี่เกินไป กรุณารอสักครู่'
  }
});

app.get('/api/delivery/status', quoteLimiter, async (req, res) => {
  try {
    const { error } = await admin
      .from('delivery_quotes')
      .select('id')
      .limit(1);

    return res.json({
      route_service_key_set: Boolean(process.env.ORS_API_KEY),
      quotes_table_ok: !error,
      quotes_table_error_code: error ? error.code || null : null
    });
  } catch (err) {
    return res.status(500).json({
      error: 'status check failed'
    });
  }
});

app.post('/api/delivery/quote', quoteLimiter, async (req, res) => {
  const code = clean(req.body.shop_code, 40).toUpperCase();
  const lat = Number(req.body.lat);
  const lng = Number(req.body.lng);

  if (
    !/^[A-Z0-9]{4,40}$/.test(code) ||
    !Number.isFinite(lat) ||
    !Number.isFinite(lng) ||
    Math.abs(lat) > 90 ||
    Math.abs(lng) > 180
  ) {
    return res.status(400).json({
      error: 'ข้อมูลตำแหน่งไม่ถูกต้อง'
    });
  }

  if (!process.env.ORS_API_KEY) {
    return res.status(503).json({
      error: 'ระบบคำนวณเส้นทางยังไม่ได้ตั้งค่า กรุณาติดต่อผู้ดูแลระบบ'
    });
  }

  try {
    const { data: shop, error: shopError } =
      await admin.from('shops')
        .select('id, is_active')
        .eq('shop_code', code)
        .maybeSingle();

    if (shopError) throw shopError;

    if (!shop || !shop.is_active) {
      return res.status(404).json({
        error: 'ไม่พบร้านค้า'
      });
    }

    const { data: row, error: cfgError } =
      await admin.from('shop_settings')
        .select('settings')
        .eq('shop_id', shop.id)
        .maybeSingle();

    if (cfgError) throw cfgError;

    const cfg = row && row.settings && row.settings.delivery;

    if (
      !cfg ||
      !Number.isFinite(Number(cfg.lat)) ||
      !Number.isFinite(Number(cfg.lng))
    ) {
      return res.status(409).json({
        error: 'ร้านยังไม่ได้ตั้งตำแหน่งร้าน'
      });
    }

    const toRad = d => d * Math.PI / 180;
    const dLat = toRad(lat - Number(cfg.lat));
    const dLng = toRad(lng - Number(cfg.lng));

    const hav =
      Math.sin(dLat / 2) ** 2 +
      Math.cos(toRad(Number(cfg.lat))) *
      Math.cos(toRad(lat)) *
      Math.sin(dLng / 2) ** 2;

    const straightKm = 12742 * Math.asin(Math.sqrt(hav));

    let km;
    let minutes;
    let coords;

    if (straightKm < 0.05) {
      km = 0;
      minutes = 1;
      coords = [
        [Number(cfg.lng), Number(cfg.lat)],
        [lng, lat]
      ];
    } else {
      const orsResponse = await fetch(
        'https://api.openrouteservice.org/v2/directions/driving-car/geojson',
        {
          method: 'POST',
          headers: {
            Authorization: process.env.ORS_API_KEY,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            coordinates: [
              [Number(cfg.lng), Number(cfg.lat)],
              [lng, lat]
            ]
          }),
          signal: AbortSignal.timeout(10000)
        }
      );

      if (orsResponse.status === 404 || orsResponse.status === 400) {
        return res.status(422).json({
          error: 'ไม่พบเส้นทางไปยังตำแหน่งนี้ ลองขยับหมุดใกล้ถนน'
        });
      }

      if (!orsResponse.ok) {
        console.error('ORS error status:', orsResponse.status);

        return res.status(502).json({
          error: 'บริการเส้นทางไม่พร้อมใช้งาน กรุณาลองใหม่'
        });
      }

      const geo = await orsResponse.json();
      const feature = geo.features && geo.features[0];
      const summary = feature &&
        feature.properties &&
        feature.properties.summary;

      if (!summary) {
        return res.status(502).json({
          error: 'บริการเส้นทางตอบกลับไม่ถูกต้อง'
        });
      }

      km = summary.distance / 1000;
      minutes = Math.max(1, Math.round(summary.duration / 60));
      coords = feature.geometry.coordinates;
    }

    const maxKm = num(cfg.max_km, 0);

    if (maxKm > 0 && km > maxKm) {
      return res.status(422).json({
        error: 'ไกลเกินระยะจัดส่งของร้าน (สูงสุด ' + maxKm + ' กม.)'
      });
    }

    const kml = Math.max(num(cfg.km_per_l, 30), 1);
    const fuel =
      (km * (cfg.round_trip ? 2 : 1)) /
      kml * Math.max(num(cfg.fuel_price, 0), 0);

    const labor = Math.max(num(cfg.labor, 0), 0);
    const maintenance = Math.max(num(cfg.maintenance, 0), 0);
    const cost = fuel + labor + maintenance;

    const fee = Math.max(
      num(cfg.min_fee, 0),
      Math.ceil(Math.max(num(cfg.per_km, 0), 0) * km)
    );

    const r2 = x => Math.round(x * 100) / 100;

    const { data: quote, error: quoteError } =
      await admin.from('delivery_quotes')
        .insert({
          shop_id: shop.id,
          lat,
          lng,
          distance_km: r2(km),
          duration_min: minutes,
          fee,
          cost: r2(cost),
          breakdown: {
            fuel: r2(fuel),
            labor,
            maintenance,
            cost: r2(cost),
            customer_fee: fee,
            profit: r2(fee - cost),
            round_trip: Boolean(cfg.round_trip)
          }
        })
        .select('id')
        .single();

    if (quoteError) throw quoteError;

    const step = Math.max(1, Math.ceil(coords.length / 250));

    const route = coords
      .filter((_, i) => i % step === 0 || i === coords.length - 1)
      .map(([x, y]) => [y, x]);

    return res.json({
      ok: true,
      quote_id: quote.id,
      distance_km: r2(km),
      duration_min: minutes,
      fee,
      route
    });

  } catch (error) {
    console.error('Quote error:', error.message);

    return res.status(500).json({
      error: 'คำนวณค่าจัดส่งไม่สำเร็จ กรุณาลองใหม่'
    });
  }
});

// ==========================================
// 13. VERIFY LICENSE
// ==========================================

app.post('/api/license/verify', authLimiter, async (req, res) => {
  const licenseKey = clean(
    req.body.license_key, 100
  ).toUpperCase();

  const shopCode = clean(
    req.body.shop_code, 24
  ).toUpperCase();

  if (!licenseKey || !shopCode) {
    return res.status(400).json({
      error: 'กรุณากรอก License และ Shop Code'
    });
  }

  try {
    const { data: license, error: licenseError } =
      await admin.from('licenses')
        .select('id, license_key, status, plan, starts_at, expires_at')
        .eq('license_key', licenseKey)
        .maybeSingle();

    if (licenseError) throw licenseError;

    if (!license) {
      await recordAttempt(shopCode, 'license_verify', false, req);

      return res.status(401).json({
        error: 'License ไม่ถูกต้อง'
      });
    }

    const { data: shop, error: shopError } =
      await admin.from('shops')
        .select('id, owner_user_id, shop_code, shop_name, license_id, is_active')
        .eq('shop_code', shopCode)
        .eq('license_id', license.id)
        .maybeSingle();

    if (shopError) throw shopError;

    if (!shop) {
      await recordAttempt(shopCode, 'license_verify', false, req);

      return res.status(401).json({
        error: 'License ไม่ตรงกับ Shop Code'
      });
    }

    if (license.status === 'revoked') {
      return res.status(403).json({
        error: 'License นี้ถูกยกเลิกแล้ว'
      });
    }

    if (license.status === 'active' || shop.is_active) {
      return res.status(409).json({
        error: 'ร้านนี้เปิดใช้งานแล้ว กรุณาเข้าสู่ระบบ'
      });
    }

    const setupToken = createSetupToken(
      shop.owner_user_id,
      shop.id,
      license.id
    );

    await recordAttempt(shopCode, 'license_verify', true, req);

    return res.json({
      ok: true,
      message: 'ยืนยัน License สำเร็จ กรุณาตั้งรหัสผ่านเจ้าของร้าน',
      setup_token: setupToken,
      shop: {
        id: shop.id,
        shop_code: shop.shop_code,
        shop_name: shop.shop_name
      }
    });

  } catch (error) {
    console.error('License verify error:', error.message);

    return res.status(500).json({
      error: 'ตรวจสอบ License ไม่สำเร็จ'
    });
  }
});

// ==========================================
// 14. SET OWNER PASSWORD - LIFETIME LICENSE
// ==========================================

app.post(
  '/api/owner/set-password',
  authLimiter,
  requireSetupToken,
  async (req, res) => {
    const password = typeof req.body.password === 'string'
      ? req.body.password
      : '';

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: 'รหัสผ่านต้องมีความยาว 8-128 ตัวอักษร'
      });
    }

    try {
      const { data: shop, error: shopError } =
        await admin.from('shops')
          .select('id, owner_user_id, license_id, is_active')
          .eq('id', req.setup.shop_id)
          .eq('owner_user_id', req.setup.sub)
          .eq('license_id', req.setup.license_id)
          .maybeSingle();

      if (shopError) throw shopError;

      if (!shop) {
        return res.status(404).json({
          error: 'ไม่พบข้อมูลร้าน'
        });
      }

      if (shop.is_active) {
        return res.status(409).json({
          error: 'ร้านนี้เปิดใช้งานแล้ว'
        });
      }

      const { error: passwordError } =
        await admin.auth.admin.updateUserById(
          req.setup.sub,
          { password }
        );

      if (passwordError) throw passwordError;

      const { error: licenseUpdateError } =
        await admin.from('licenses')
          .update({
            status: 'active',
            starts_at: new Date().toISOString(),
            expires_at: null
          })
          .eq('id', shop.license_id);

      if (licenseUpdateError) throw licenseUpdateError;

      const { error: shopUpdateError } =
        await admin.from('shops')
          .update({ is_active: true })
          .eq('id', shop.id);

      if (shopUpdateError) throw shopUpdateError;

      return res.json({
        ok: true,
        message: 'ตั้งรหัสผ่านและเปิดใช้งาน License ถาวรสำเร็จ',
        license_type: 'lifetime'
      });

    } catch (error) {
      console.error('Set password error:', error.message);

      return res.status(500).json({
        error: 'ตั้งรหัสผ่านไม่สำเร็จ กรุณาลองใหม่'
      });
    }
  }
);

// ==========================================
// 15. OWNER LOGIN - LIFETIME LICENSE
// ==========================================

app.post('/api/owner/login', authLimiter, async (req, res) => {
  const shopCode = clean(
    req.body.shop_code, 24
  ).toUpperCase();

  const password = typeof req.body.password === 'string'
    ? req.body.password
    : '';

  if (!shopCode || !password) {
    return res.status(400).json({
      error: 'กรุณากรอก Shop Code และรหัสผ่าน'
    });
  }

  try {
    const { data: shop, error: shopError } =
      await admin.from('shops')
        .select('id, owner_user_id, license_id, shop_code, shop_name, email, is_active')
        .eq('shop_code', shopCode)
        .maybeSingle();

    if (shopError) throw shopError;

    if (
      !shop ||
      !shop.email ||
      !shop.is_active ||
      !shop.license_id
    ) {
      await recordAttempt(shopCode, 'owner_login', false, req);

      return res.status(401).json({
        error: 'Shop Code หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    const { data: license, error: licenseError } =
      await admin.from('licenses')
        .select('status')
        .eq('id', shop.license_id)
        .maybeSingle();

    if (licenseError) throw licenseError;

    if (!license || license.status !== 'active') {
      await recordAttempt(shopCode, 'owner_login', false, req);

      return res.status(403).json({
        error: 'License ถูกระงับหรือยกเลิก'
      });
    }

    const { data: authData, error: authError } =
      await publicClient.auth.signInWithPassword({
        email: shop.email,
        password
      });

    if (
      authError ||
      !authData ||
      !authData.user ||
      authData.user.id !== shop.owner_user_id ||
      !authData.session
    ) {
      await recordAttempt(shopCode, 'owner_login', false, req);

      return res.status(401).json({
        error: 'Shop Code หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    await recordAttempt(shopCode, 'owner_login', true, req);

    return res.json({
      ok: true,
      access_token: authData.session.access_token,
      refresh_token: authData.session.refresh_token,
      token_type: authData.session.token_type,
      expires_in: authData.session.expires_in,
      shop: {
        id: shop.id,
        shop_code: shop.shop_code,
        shop_name: shop.shop_name
      }
    });

  } catch (error) {
    console.error('Owner login error:', error.message);

    return res.status(500).json({
      error: 'เข้าสู่ระบบไม่สำเร็จ กรุณาลองใหม่'
    });
  }
});

// ==========================================
// 16. ADMIN - RENEW ONE SHOP
// ==========================================

app.post(
  '/api/admin/shops/:id/renew',
  requireSystemAdmin,
  async (req, res) => {
    const shopId = clean(req.params.id, 50);
    const months = Number(req.body.months);
    const amount = req.body.amount == null || req.body.amount === ''
      ? null
      : Number(req.body.amount);
    const note = clean(req.body.note, 500);

    if (
      !/^[0-9a-f-]{36}$/i.test(shopId) ||
      !Number.isInteger(months) ||
      months < 1 ||
      months > 120 ||
      (amount !== null && (!Number.isFinite(amount) || amount < 0))
    ) {
      return res.status(400).json({
        error: 'ข้อมูลการต่อบริการไม่ถูกต้อง'
      });
    }

    try {
      const { data: shop, error: shopError } =
        await admin.from('shops')
          .select('id, shop_name, shop_code, is_active, license_id')
          .eq('id', shopId)
          .maybeSingle();

      if (shopError) throw shopError;

      if (!shop) {
        return res.status(404).json({
          error: 'ไม่พบร้านที่ต้องการต่อบริการ'
        });
      }

      const { data: latest, error: latestError } =
        await admin.from('shop_service_payments')
          .select('service_until')
          .eq('shop_id', shopId)
          .order('service_until', { ascending: false })
          .limit(1)
          .maybeSingle();

      if (latestError) throw latestError;

      const today = dateString(new Date());
      const serviceFrom = latest && latest.service_until > today
        ? latest.service_until
        : today;

      const serviceUntil = addMonths(serviceFrom, months);

      const { data: payment, error: paymentError } =
        await admin.from('shop_service_payments')
          .insert({
            shop_id: shopId,
            months,
            amount,
            service_from: serviceFrom,
            service_until: serviceUntil,
            paid_at: new Date().toISOString(),
            note: note || null
          })
          .select('*')
          .single();

      if (paymentError) throw paymentError;

      return res.json({
        ok: true,
        message: 'บันทึกการต่อบริการสำเร็จ License เดิมยังคงเดิม',
        shop: {
          id: shop.id,
          shop_name: shop.shop_name,
          shop_code: shop.shop_code
        },
        service: payment,
        license_changed: false
      });

    } catch (error) {
      console.error('Renew shop error:', error.message);

      return res.status(500).json({
        error: 'บันทึกการต่อบริการไม่สำเร็จ'
      });
    }
  }
);

// ==========================================
// 17. ADMIN - RENEW ALL ACTIVE SHOPS
// ==========================================

app.post(
  '/api/admin/shops/renew-all',
  requireSystemAdmin,
  async (req, res) => {
    const months = Number(req.body.months);
    const amount = req.body.amount == null || req.body.amount === ''
      ? null
      : Number(req.body.amount);
    const note = clean(req.body.note, 500);

    if (
      req.body.confirm_all !== true ||
      !Number.isInteger(months) ||
      months < 1 ||
      months > 120 ||
      (amount !== null && (!Number.isFinite(amount) || amount < 0))
    ) {
      return res.status(400).json({
        error: 'กรุณายืนยัน confirm_all และตรวจสอบข้อมูลการต่อบริการ'
      });
    }

    try {
      const { data: shops, error: shopsError } =
        await admin.from('shops')
          .select('id, shop_name, shop_code')
          .eq('is_active', true)
          .eq('is_test', false)
          .limit(10000);

      if (shopsError) throw shopsError;

      if (!shops || shops.length === 0) {
        return res.json({
          ok: true,
          message: 'ไม่มีร้านที่เปิดใช้งานให้ต่อบริการ',
          renewed: 0,
          failed: 0,
          license_changed: false
        });
      }

      let renewed = 0;
      const failures = [];

      for (const shop of shops) {
        try {
          const { data: latest, error: latestError } =
            await admin.from('shop_service_payments')
              .select('service_until')
              .eq('shop_id', shop.id)
              .order('service_until', { ascending: false })
              .limit(1)
              .maybeSingle();

          if (latestError) throw latestError;

          const today = dateString(new Date());
          const serviceFrom =
            latest && latest.service_until > today
              ? latest.service_until
              : today;

          const serviceUntil = addMonths(serviceFrom, months);

          const { error: insertError } =
            await admin.from('shop_service_payments')
              .insert({
                shop_id: shop.id,
                months,
                amount,
                service_from: serviceFrom,
                service_until: serviceUntil,
                paid_at: new Date().toISOString(),
                note: note || 'ต่อบริการพร้อมกันทุกร้าน'
              });

          if (insertError) throw insertError;

          renewed++;

        } catch (err) {
          console.error(
            'Bulk renewal failed:',
            shop.id,
            err.message
          );

          failures.push({
            shop_id: shop.id,
            shop_code: shop.shop_code,
            error: 'บันทึกไม่สำเร็จ'
          });
        }
      }

      return res.json({
        ok: failures.length === 0,
        message: 'ดำเนินการต่อบริการร้านที่เปิดใช้งานแล้ว',
        total: shops.length,
        renewed,
        failed: failures.length,
        failures,
        license_changed: false
      });

    } catch (error) {
      console.error('Renew all error:', error.message);

      return res.status(500).json({
        error: 'ต่อบริการทุกร้านไม่สำเร็จ'
      });
    }
  }
);

// ==========================================
// 18. ADMIN - DELETE ONE SHOP
// ==========================================

app.delete(
  '/api/admin/shops/:id',
  requireSystemAdmin,
  async (req, res) => {
    const shopId = clean(req.params.id, 50);

    if (!/^[0-9a-f-]{36}$/i.test(shopId)) {
      return res.status(400).json({
        error: 'รหัสร้านไม่ถูกต้อง'
      });
    }

    if (req.body.confirm_delete !== true) {
      return res.status(400).json({
        error: 'กรุณายืนยัน confirm_delete เป็น true'
      });
    }

    try {
      const { data, error } = await admin.rpc(
        'admin_delete_shop',
        { p_shop_id: shopId }
      );

      if (error) throw error;

      return res.json({
        ok: true,
        message: 'ลบร้านและข้อมูลที่เกี่ยวข้องสำเร็จ',
        result: data
      });

    } catch (error) {
      console.error('Delete shop error:', error.message);

      if (
        String(error.message || '').includes('SHOP_NOT_FOUND')
      ) {
        return res.status(404).json({
          error: 'ไม่พบร้านที่ต้องการลบ'
        });
      }

      return res.status(500).json({
        error: 'ลบร้านไม่สำเร็จ กรุณาตรวจสอบข้อมูลที่เกี่ยวข้อง'
      });
    }
  }
);

// ==========================================
// 19. ERROR HANDLER
// ==========================================

app.use((err, req, res, next) => {
  if (err.message === 'Origin not allowed') {
    return res.status(403).json({
      error: 'เว็บไซต์นี้ไม่ได้รับอนุญาตให้เรียก API'
    });
  }

  console.error('Server error:', err.message);

  return res.status(500).json({
    error: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์'
  });
});

// ==========================================
// 20. START SERVER
// ==========================================

app.listen(PORT, () => {
  console.log(`AUTO SHOP PRO API running on port ${PORT}`);
});
