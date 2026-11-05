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
const TRIAL_DAYS = Number(process.env.TRIAL_DAYS || 14);
const TOKEN_MINUTES = Number(
  process.env.SETUP_TOKEN_MINUTES || 20
);

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

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization'
  ]
}));

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
// 4. SUPABASE CONNECTION
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
// 5. HELPER FUNCTIONS
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

// ส่ง License Key ไปยังอีเมลเจ้าของร้านผ่าน Gmail SMTP
// Render ต้องตั้งค่า GMAIL_USER และ GMAIL_APP_PASSWORD
async function sendLicenseEmail({
  to,
  ownerName,
  shopName,
  shopCode,
  licenseKey
}) {
  const gmailUser = String(process.env.GMAIL_USER || '').trim();
  const appPassword = String(process.env.GMAIL_APP_PASSWORD || '')
    .replace(/\s+/g, '');

  if (!gmailUser || !appPassword) {
    const error = new Error('EMAIL_NOT_CONFIGURED');
    error.code = 'EMAIL_NOT_CONFIGURED';
    throw error;
  }

  const safeOwnerName = escapeHtml(ownerName);
  const safeShopName = escapeHtml(shopName);
  const safeShopCode = escapeHtml(shopCode);
  const safeLicenseKey = escapeHtml(licenseKey);

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
    const result = await transporter.sendMail({
      from: {
        name: 'AUTO SHOP PRO',
        address: gmailUser
      },
      to,
      subject: 'License Key สำหรับ AUTO SHOP PRO',
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.7;color:#222">
          <h2>สมัคร AUTO SHOP PRO สำเร็จ</h2>
          <p>สวัสดีคุณ ${safeOwnerName}</p>
          <p>ระบบได้รับข้อมูลสมัครร้านของคุณแล้ว</p>
          <p><strong>ชื่อร้าน:</strong> ${safeShopName}</p>
          <p><strong>Shop Code:</strong> ${safeShopCode}</p>
          <p><strong>License Key:</strong></p>
          <p style="font-size:20px;font-weight:bold;letter-spacing:1px">
            ${safeLicenseKey}
          </p>
          <p>กรุณาเก็บ License Key นี้ไว้ เพื่อใช้ยืนยันก่อนตั้งรหัสผ่านเจ้าของร้าน</p>
          <p>หากไม่ได้เป็นผู้สมัคร กรุณาเพิกเฉยต่ออีเมลฉบับนี้</p>
          <p>AUTO SHOP PRO</p>
        </div>
      `,
      text:
        `สมัคร AUTO SHOP PRO สำเร็จ\n` +
        `ชื่อร้าน: ${ownerName}\n` +
        `Shop Code: ${shopCode}\n` +
        `License Key: ${licenseKey}\n` +
        `กรุณาเก็บ License Key นี้ไว้เพื่อใช้ยืนยันก่อนตั้งรหัสผ่าน`
    });

    return result;
  } catch (err) {
    console.error('Gmail SMTP email error:', err && err.message ? err.message : err);
        if (licenseId) {
      await admin.from('licenses').delete().eq('id', licenseId);
    }

    if (authUserId) {
      await admin.auth.admin.deleteUser(authUserId);
    }

    await recordAttempt(
      email || 'unknown',
      'register',
      false,
      req
    );

    if (error.code === 'EMAIL_NOT_CONFIGURED') {
      return res.status(503).json({
        error: 'ระบบส่งอีเมลยังตั้งค่าไม่ครบ กรุณาติดต่อผู้ดูแลระบบ'
      });
    }

    if (error.code === 'EMAIL_SEND_FAILED') {
      return res.status(503).json({
        error: 'สร้างข้อมูลสมัครไม่สำเร็จ เนื่องจากส่งอีเมล License ไม่สำเร็จ กรุณาลองใหม่'
      });
    }

    return res.status(500).json({
      error: 'สมัครร้านไม่สำเร็จ กรุณาลองใหม่ภายหลัง'
    });
  }
});

// ==========================================
// 8. VERIFY LICENSE
// ==========================================

app.post('/api/license/verify', authLimiter, async (req, res) => {

  const licenseKey = clean(
    req.body.license_key,
    100
  ).toUpperCase();

  const shopCode = clean(
    req.body.shop_code,
    24
  ).toUpperCase();

  if (!licenseKey || !shopCode) {
    return res.status(400).json({
      error: 'กรุณากรอก License และ Shop Code'
    });
  }

  try {

    const { data: license, error: licenseError } =
      await admin
        .from('licenses')
        .select('id, license_key, status, plan, starts_at, expires_at')
        .eq('license_key', licenseKey)
        .maybeSingle();

    if (licenseError) throw licenseError;

    if (!license) {
      await recordAttempt(
        shopCode,
        'license_verify',
        false,
        req
      );

      return res.status(401).json({
        error: 'License ไม่ถูกต้อง'
      });
    }

    const { data: shop, error: shopError } =
      await admin
        .from('shops')
        .select('id, owner_user_id, shop_code, shop_name, license_id, is_active')
        .eq('shop_code', shopCode)
        .eq('license_id', license.id)
        .maybeSingle();

    if (shopError) throw shopError;

    if (!shop) {
      await recordAttempt(
        shopCode,
        'license_verify',
        false,
        req
      );

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

    await recordAttempt(
      shopCode,
      'license_verify',
      true,
      req
    );

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
// 9. SET OWNER PASSWORD
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
        await admin
          .from('shops')
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

      const now = new Date();
      const expiresAt = new Date(
        now.getTime() + TRIAL_DAYS * 24 * 60 * 60 * 1000
      );

      const { error: licenseUpdateError } =
        await admin
          .from('licenses')
          .update({
            status: 'active',
            starts_at: now.toISOString(),
            expires_at: expiresAt.toISOString()
          })
          .eq('id', shop.license_id);

      if (licenseUpdateError) throw licenseUpdateError;

      const { error: shopUpdateError } =
        await admin
          .from('shops')
          .update({
            is_active: true
          })
          .eq('id', shop.id);

      if (shopUpdateError) throw shopUpdateError;

      return res.json({
        ok: true,
        message: 'ตั้งรหัสผ่านและเปิดใช้งานร้านสำเร็จ',
        trial_days: TRIAL_DAYS,
        expires_at: expiresAt.toISOString()
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
// 10. OWNER LOGIN
// ==========================================

app.post('/api/owner/login', authLimiter, async (req, res) => {

  const shopCode = clean(
    req.body.shop_code,
    24
  ).toUpperCase();

  const password =
    typeof req.body.password === 'string'
      ? req.body.password
      : '';

  if (!shopCode || !password) {
    return res.status(400).json({
      error: 'กรุณากรอก Shop Code และรหัสผ่าน'
    });
  }

  try {

    const { data: shop, error: shopError } =
      await admin
        .from('shops')
        .select(
          'id, owner_user_id, license_id, shop_code, shop_name, email, is_active'
        )
        .eq('shop_code', shopCode)
        .maybeSingle();

    if (shopError) throw shopError;

    if (
      !shop ||
      !shop.email ||
      !shop.is_active ||
      !shop.license_id
    ) {
      await recordAttempt(
        shopCode,
        'owner_login',
        false,
        req
      );

      return res.status(401).json({
        error: 'Shop Code หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    const { data: license, error: licenseError } =
      await admin
        .from('licenses')
        .select('status, expires_at')
        .eq('id', shop.license_id)
        .maybeSingle();

    if (licenseError) throw licenseError;

    if (
      !license ||
      license.status !== 'active' ||
      (
        license.expires_at &&
        new Date(license.expires_at).getTime() < Date.now()
      )
    ) {
      await recordAttempt(
        shopCode,
        'owner_login',
        false,
        req
      );

      return res.status(403).json({
        error: 'License หมดอายุหรือถูกระงับ'
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
      await recordAttempt(
        shopCode,
        'owner_login',
        false,
        req
      );

      return res.status(401).json({
        error: 'Shop Code หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    await recordAttempt(
      shopCode,
      'owner_login',
      true,
      req
    );

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
// 11. ERROR HANDLER
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
// 12. START SERVER
// ==========================================

app.listen(PORT, () => {
  console.log(
    `AUTO SHOP PRO API running on port ${PORT}`
  );
});
app.post('/api/owner/login', authLimiter, async (req, res) => {

  const shopCode = clean(
    req.body.shop_code,
    24
  ).toUpperCase();

  const password =
    typeof req.body.password === 'string'
      ? req.body.password
      : '';

  if (!shopCode || !password) {
    return res.status(400).json({
      error: 'กรุณากรอก Shop Code และรหัสผ่าน'
    });
  }

  try {

    const { data: shop, error: shopError } =
      await admin
        .from('shops')
        .select(
          'id, owner_user_id, license_id, shop_code, shop_name, email, is_active'
        )
        .eq('shop_code', shopCode)
        .maybeSingle();

    if (shopError) throw shopError;

    if (
      !shop ||
      !shop.email ||
      !shop.is_active ||
      !shop.license_id
    ) {
      await recordAttempt(
        shopCode,
        'owner_login',
        false,
        req
      );

      return res.status(401).json({
        error: 'Shop Code หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    const { data: license, error: licenseError } =
      await admin
        .from('licenses')
        .select('status, expires_at')
        .eq('id', shop.license_id)
        .maybeSingle();

    if (licenseError) throw licenseError;

    if (
      !license ||
      license.status !== 'active' ||
      (
        license.expires_at &&
        new Date(license.expires_at).getTime() < Date.now()
      )
    ) {
      await recordAttempt(
        shopCode,
        'owner_login',
        false,
        req
      );

      return res.status(403).json({
        error: 'License หมดอายุหรือถูกระงับ'
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
      await recordAttempt(
        shopCode,
        'owner_login',
        false,
        req
      );

      return res.status(401).json({
        error: 'Shop Code หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    await recordAttempt(
      shopCode,
      'owner_login',
      true,
      req
    );

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
// 11. ERROR HANDLER
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
// 12. START SERVER
// ==========================================

app.listen(PORT, () => {
  console.log(
    `AUTO SHOP PRO API running on port ${PORT}`
  );
});
