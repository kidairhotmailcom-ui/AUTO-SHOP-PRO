
'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const { createClient } = require('@supabase/supabase-js');

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

async function recordAttempt(identifier, type, success, req) {
  const { error } = await admin
    .from('login_attempts')
    .insert({
      login_identifier: String(identifier || 'unknown').slice(0, 180),
      attempt_type: type,
      success: Boolean(success),
      ip_hash: hashIp(req.ip)
    });

  if (error) {
    console.error('Login attempt log error:', error.message);
  }
}

function createSetupToken(userId, shopId, licenseId) {
  return jwt.sign(
    {
      sub: userId,
      shop_id: shopId,
      license_id: licenseId,
      purpose: 'set_owner_password'
    },
    process.env.JWT_SECRET,
    {
      expiresIn: `${TOKEN_MINUTES}m`,
      issuer: 'auto-shop-pro'
    }
  );
}

function requireSetupToken(req, res, next) {
  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ')
    ? header.substring(7)
    : '';

  if (!token) {
    return res.status(401).json({
      error: 'กรุณายืนยัน License ก่อนตั้งรหัสผ่าน'
    });
  }

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET,
      { issuer: 'auto-shop-pro' }
    );

    if (payload.purpose !== 'set_owner_password') {
      throw new Error('Invalid token purpose');
    }

    req.setup = payload;

    next();

  } catch (error) {
    return res.status(401).json({
      error: 'Setup Token ไม่ถูกต้องหรือหมดอายุ'
    });
  }
}

// ==========================================
// 6. HEALTH CHECK
// ==========================================

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'AUTO SHOP PRO API',
    time: new Date().toISOString()
  });
});

// ==========================================
// 7. REGISTER SHOP
// ==========================================

app.post('/api/register', authLimiter, async (req, res) => {

  const ownerName = clean(req.body.owner_name, 120);
  const shopName = clean(req.body.shop_name, 160);
  const address = clean(req.body.address, 200);

  let shopCode = clean(
    req.body.shop_code,
    24
  ).toUpperCase();

  const phone = clean(req.body.phone, 30);

  const email = clean(
    req.body.email,
    254
  ).toLowerCase();

  if (
    !ownerName ||
    !shopName ||
    (shopCode && !validShopCode(shopCode)) ||
    !validEmail(email)
  ) {
    return res.status(400).json({
      error: 'ข้อมูลสมัครร้านไม่ครบหรือไม่ถูกต้อง',
      required: [
        'owner_name',
        'shop_name',
        'email'
      ]
    });
  }

  let authUserId = null;
  let licenseId = null;
  let shopId = null;

  try {

    // สร้าง Shop Code อัตโนมัติ หากไม่ได้ส่งมา
    if (!shopCode) {
      shopCode = 'SHP-' +
        crypto.randomBytes(6).toString('hex').toUpperCase();
    }

    // ตรวจสอบ Shop Code ซ้ำ
    const { data: existingShop, error: checkError } =
      await admin
        .from('shops')
        .select('id')
        .eq('shop_code', shopCode)
        .maybeSingle();

    if (checkError) throw checkError;

    if (existingShop) {
      return res.status(409).json({
        error: 'Shop Code นี้ถูกใช้งานแล้ว'
      });
    }

    const { data: authData, error: authError } =
      await admin.auth.admin.createUser({
  email,
  password: makeTemporaryPassword(),
  email_confirm: false,
  user_metadata: {
    owner_name: ownerName,
    shop_address: address,
    app: 'AUTO_SHOP_PRO'
  }
});

    if (authError) throw authError;

    authUserId = authData.user.id;

    const licenseKey = makeLicenseKey();

    const { data: license, error: licenseError } =
      await admin
        .from('licenses')
        .insert({
          license_key: licenseKey,
          status: 'suspended',
          plan: 'trial',
          starts_at: null,
          expires_at: null
        })
        .select('id')
        .single();

    if (licenseError) throw licenseError;

    licenseId = license.id;

    const { data: shop, error: shopError } =
      await admin
        .from('shops')
        .insert({
          owner_user_id: authUserId,
          license_id: licenseId,
          shop_code: shopCode,
          shop_name: shopName,
          owner_name: ownerName,
          phone: phone || null,
          email,
          is_active: false
        })
        .select('id, shop_code, shop_name')
        .single();

    if (shopError) throw shopError;

    shopId = shop.id;

    await recordAttempt(
      shopCode,
      'register',
      true,
      req
    );

    return res.status(201).json({
      ok: true,
      message: 'สมัครร้านสำเร็จ กรุณาเก็บ License Key',
      license_key: licenseKey,
      shop: {
        id: shop.id,
        shop_code: shop.shop_code,
        shop_name: shop.shop_name
      }
    });

   } catch (error) {

    console.error('Registration error:', error.message);

    if (shopId) {
      await admin.from('shops').delete().eq('id', shopId);
    }

    if (licenseId) {
      await admin.from('licenses').delete().eq('id', licenseId);
    }

    if (authUserId) {
      await admin.auth.admin.deleteUser(authUserId);
    }

    await recordAttempt(
      shopCode || email,
      'register',
      false,
      req
    );

    const emailNotConfigured = error.message === 'EMAIL_NOT_CONFIGURED';

    return res.status(emailNotConfigured ? 503 : 500).json({
      error: emailNotConfigured
        ? 'ระบบส่งอีเมลยังตั้งค่าไม่ครบ กรุณาติดต่อผู้ดูแลระบบ'
        : 'สมัครไม่สำเร็จ กรุณาตรวจสอบข้อมูลและลองใหม่'
    });
  }
});
// ==========================================
// 8. VERIFY LICENSE
// ==========================================

app.post('/api/license/verify', authLimiter, async (req, res) => {

  const shopCode = clean(
    req.body.shop_code,
    24
  ).toUpperCase();

  const licenseKey = clean(
    req.body.license_key,
    80
  ).toUpperCase();

  if (!shopCode || !licenseKey) {
    return res.status(400).json({
      error: 'กรุณากรอก Shop Code และ License Key'
    });
  }

  try {

    const { data: shop, error: shopError } =
      await admin
        .from('shops')
        .select(
          'id, owner_user_id, license_id, shop_code, shop_name'
        )
        .eq('shop_code', shopCode)
        .maybeSingle();

    if (shopError) throw shopError;

    if (!shop || !shop.license_id) {
      await recordAttempt(
        shopCode,
        'license_verify',
        false,
        req
      );

      return res.status(401).json({
        error: 'Shop Code หรือ License Key ไม่ถูกต้อง'
      });
    }

    const { data: license, error: licenseError } =
      await admin
        .from('licenses')
        .select('id, license_key, status, expires_at')
        .eq('id', shop.license_id)
        .maybeSingle();

    if (licenseError) throw licenseError;

    const storedKey = license?.license_key || '';

    const keyMatches =
      storedKey.length === licenseKey.length &&
      crypto.timingSafeEqual(
        Buffer.from(storedKey),
        Buffer.from(licenseKey)
      );

    if (
      !license ||
      !keyMatches ||
      license.status !== 'suspended'
    ) {
      await recordAttempt(
        shopCode,
        'license_verify',
        false,
        req
      );

      return res.status(401).json({
        error: 'License ไม่ถูกต้องหรือถูกใช้งานแล้ว'
      });
    }

    const token = createSetupToken(
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
      setup_token: token,
      expires_in_minutes: TOKEN_MINUTES,
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

    const password =
      typeof req.body.password === 'string'
        ? req.body.password
        : '';

    if (password.length < 10 || password.length > 128) {
      return res.status(400).json({
        error: 'รหัสผ่านต้องมีความยาว 10-128 ตัวอักษร'
      });
    }

    try {

      const { data: shop, error: shopError } =
        await admin
          .from('shops')
          .select('id, owner_user_id, license_id')
          .eq('id', req.setup.shop_id)
          .eq('owner_user_id', req.setup.sub)
          .eq('license_id', req.setup.license_id)
          .maybeSingle();

      if (shopError) throw shopError;

      if (!shop) {
        return res.status(401).json({
          error: 'ข้อมูลร้านไม่ตรงกับ Setup Token'
        });
      }

      const { error: passwordError } =
        await admin.auth.admin.updateUserById(
          req.setup.sub,
          {
            password,
            email_confirm: true
          }
        );

      if (passwordError) throw passwordError;

      const { data: activated, error: activateError } =
        await admin.rpc('activate_shop_license', {
          p_shop_id: shop.id,
          p_license_id: shop.license_id,
          p_trial_days: TRIAL_DAYS
        });

      if (activateError) throw activateError;

      if (!activated) {
        throw new Error('License activation failed');
      }

      return res.json({
        ok: true,
        message: 'ตั้งรหัสผ่านและเปิดใช้งานร้านสำเร็จ',
        shop_id: shop.id,
        trial_days: TRIAL_DAYS
      });

    } catch (error) {

      console.error('Set password error:', error.message);

      return res.status(500).json({
        error: 'ตั้งรหัสผ่านหรือเปิดใช้งานร้านไม่สำเร็จ'
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
      !authData.user ||
      authData.user.id !== shop.owner_user_id
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
