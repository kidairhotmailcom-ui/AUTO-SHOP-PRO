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
