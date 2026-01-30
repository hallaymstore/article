const express = require('express');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const sanitizeHtml = require('sanitize-html');
const { exec } = require('child_process');
const xml2js = require('xml2js');
const https = require('https');
const crypto = require('crypto');
const puppeteer = require('puppeteer');
let PDFDocument, rgb, StandardFonts;
try { ({ PDFDocument, rgb, StandardFonts } = require('pdf-lib')); } catch (e) {
  console.warn('pdf-lib not installed. Install with: npm i pdf-lib');
}



dotenv.config();

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// Eng oson yechim - CSP'ni vaqtincha o'chirish:
app.use(helmet({
    contentSecurityPolicy: false
}));

app.use(cors({
    origin: true,
    credentials: true,
    methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allowedHeaders: ["Content-Type","Authorization","X-Admin-Token" ]
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
});
app.use('/api/', apiLimiter);

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://abumafia0:abumafia0@abumafia.h1trttg.mongodb.net/sci12?appName=abumafia');

// MongoDB Schemas & Models
// YANGI schema:
const articleSchema = new mongoose.Schema({
    title: { type: String, required: true, index: true },
    slug: { type: String, required: true, unique: true, index: true },
    author: { type: String, required: true, index: true },
    // YANGI: Kun/Oy/Yil uchun maydonlar
    publicationDate: { type: Date, required: true }, // <-- Yangi maydon
    abstract: { type: String, required: true },
    introduction: { type: String, required: true },
    body: [{ 
        heading: String,
        content: String 
    }],
    conclusion: { type: String, required: true },
    references: [String],
    coverImage: { type: String, required: true },
    coverImagePublicId: { type: String, default: '' },
    pdfUrl: { type: String, required: true },
    pdfPublicId: { type: String, default: '' },
    generatedPdfUrl: { type: String, default: '' },
    generatedPdfPublicId: { type: String, default: '' },
    generatedPdfUpdatedAt: { type: Date },
    // --- Journal metadata (optional / for SCI-Journal)
    journal: { type: String, default: 'HALLAYM SCI-Journal' },
    issnOnline: { type: String, default: 'Pending' },
    issueId: { type: mongoose.Schema.Types.ObjectId, ref: 'Issue', index: true },
    volume: { type: Number },
    issue: { type: Number },
    year: { type: Number },
    doi: { type: String, default: '' },
    license: { type: String, default: 'CC BY 4.0' },
    keywords: { type: [String], default: [] },
    authors: [{
        name: String,
        affiliation: String,
        orcid: String,
        email: String
    }],
    receivedAt: { type: Date },
    acceptedAt: { type: Date },
    publishedAt: { type: Date },
    pages: { type: String, default: '' },
    section: { type: String, default: 'Research Article' },
    views: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const ratingSchema = new mongoose.Schema({
    articleId: { type: mongoose.Schema.Types.ObjectId, ref: 'Article', index: true },
    rating: { type: Number, min: 1, max: 5, required: true },
    userIp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: '30d' } // Auto delete after 30 days
});

const commentSchema = new mongoose.Schema({
    articleId: { type: mongoose.Schema.Types.ObjectId, ref: 'Article', index: true },
    name: { type: String, default: 'Anonymous' },
    comment: { type: String, required: true },
    userIp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const contactMessageSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

// ---- Journal system schemas (HALLAYM SCI-Journal)
const journalSettingsSchema = new mongoose.Schema({
    journalTitle: { type: String, default: 'HALLAYM SCI-Journal' },
    issnOnline: { type: String, default: 'Pending' },
    issnPrint: { type: String, default: '' },
    publisher: { type: String, default: 'Hallaym' },
    scope: { type: String, default: 'Multidisciplinary' },
    country: { type: String, default: 'Uzbekistan' },
    contactEmail: { type: String, default: 'admin@hallaym.site' },
    defaultLicense: { type: String, default: 'CC BY 4.0' },
    siteUrl: { type: String, default: 'https://theglobalscience.org' },
    logoUrl: { type: String, default: '' },
    aboutText: { type: String, default: '' },

    updatedAt: { type: Date, default: Date.now }
});

const issueSchema = new mongoose.Schema({
    volume: { type: Number, required: true },
    number: { type: Number, required: true },
    year: { type: Number, required: true },
    title: { type: String, default: '' },
    description: { type: String, default: '' },
    coverImage: { type: String, default: '' },
    publishedAt: { type: Date },
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
    createdAt: { type: Date, default: Date.now }
});
issueSchema.index({ volume: 1, number: 1, year: 1 }, { unique: true });

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
    roles: { type: [String], default: ['author'] }, // author, reviewer, editor, admin
    profile: {
        name: { type: String, default: '' },
        affiliation: { type: String, default: '' },
        orcid: { type: String, default: '' }
    },
    createdAt: { type: Date, default: Date.now }
});

const submissionSchema = new mongoose.Schema({
    title: { type: String, required: true, index: true },
    slug: { type: String, required: true, unique: true, index: true },
    authors: [{
        name: String,
        affiliation: String,
        orcid: String,
        email: String
    }],
    abstract: { type: String, default: '' },
    keywords: { type: [String], default: [] },
    coverLetter: { type: String, default: '' },
    manuscriptPdfUrl: { type: String, required: true },
    status: {
        type: String,
        enum: ['submitted', 'screening', 'under_review', 'revision', 'accepted', 'copyediting', 'typesetting', 'scheduled', 'published', 'rejected'],
        default: 'submitted'
    },
    decision: { type: String, enum: ['pending', 'accept', 'minor', 'major', 'reject'], default: 'pending' },
    authorUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    editorNote: { type: String, default: '' },
    scheduledIssueId: { type: mongoose.Schema.Types.ObjectId, ref: 'Issue' },
    history: [{
        at: { type: Date, default: Date.now },
        by: { type: String, default: '' },
        action: { type: String, default: '' },
        note: { type: String, default: '' }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const reviewSchema = new mongoose.Schema({
    submissionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Submission', required: true, index: true },
    reviewerUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    status: { type: String, enum: ['invited', 'accepted', 'declined', 'submitted'], default: 'invited' },
    recommendation: { type: String, enum: ['accept', 'minor', 'major', 'reject'], default: 'major' },
    commentsToAuthor: { type: String, default: '' },
    commentsToEditor: { type: String, default: '' },
    submittedAt: { type: Date }
});

const Article = mongoose.model('Article', articleSchema);
const Rating = mongoose.model('Rating', ratingSchema);
const Comment = mongoose.model('Comment', commentSchema);
const ContactMessage = mongoose.model('ContactMessage', contactMessageSchema);

const JournalSettings = mongoose.model('JournalSettings', journalSettingsSchema);
const Issue = mongoose.model('Issue', issueSchema);
const User = mongoose.model('User', userSchema);
const Submission = mongoose.model('Submission', submissionSchema);
const Review = mongoose.model('Review', reviewSchema);

// Cloudinary configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});
/** Upload a PDF buffer to Cloudinary as RAW and return { secure_url, public_id } */
function uploadBufferToCloudinary(buffer, { folder = 'tgs/generated', filename = 'document.pdf' } = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      resource_type: 'raw',
      folder,
      public_id: `${folder}/${Date.now()}_${safeFileName(filename).replace(/\.pdf$/i,'')}`,
      overwrite: true,
      use_filename: false,
      unique_filename: false
    };
    const stream = cloudinary.uploader.upload_stream(opts, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
    stream.end(buffer);
  });
}



// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Authentication middleware
// Authentication middleware (Admin)
// Accepts token via:
//   - Authorization: Bearer <token>
//   - X-Admin-Token: <token>
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization || '';
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const headerToken = (req.headers['x-admin-token'] || '').toString().trim();
    const token = bearer || headerToken;

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded?.username === process.env.ADMIN_USERNAME) {
            req.admin = { username: decoded.username };
            return next();
        }
        return res.status(403).json({ error: 'Invalid credentials' });
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// ---- User auth (authors/reviewers/editors)
function signUserToken(user) {
    return jwt.sign(
        { sub: user._id.toString(), roles: user.roles, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    );
}

function authenticateUser(requiredRoles = []) {
    return (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'No token provided' });
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            if (requiredRoles.length) {
                const roles = decoded.roles || [];
                const ok = requiredRoles.some(r => roles.includes(r));
                if (!ok) return res.status(403).json({ error: 'Forbidden' });
            }
            next();
        } catch (e) {
            return res.status(401).json({ error: 'Invalid token' });
        }
    };
}

// ---- Ensure journal settings exist
async function ensureJournalSettings() {
    const existing = await JournalSettings.findOne();
    if (existing) return existing;
    return await JournalSettings.create({
        journalTitle: 'The Global Science',
        issnOnline: 'Pending',
        publisher: 'The Global Science',
        scope: 'Multidisciplinary',
        country: 'Uzbekistan',
        contactEmail: 'info@theglobalscience.org',
        siteUrl: 'https://theglobalscience.org',
        logoUrl: process.env.SITE_LOGO_URL || '',
        aboutText: 'The Global Science is an open-access publishing platform for peer-reviewed research. Visit theglobalscience.org for submissions, archives, and editorial information.',
        defaultLicense: 'CC BY 4.0'
    });
}

// Email transporter
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Generate slug from title
function generateSlug(title) {
    return title
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/--+/g, '-')
        .trim();
}

// ---- Base URL helper (for sitemap/robots)
// Prefer BASE_URL env for production (e.g., https://journal.example.com)
// Fallback to request host for local/dev.
function getBaseUrl(req) {
    const fromEnv = process.env.BASE_URL;
    if (fromEnv && String(fromEnv).trim()) return String(fromEnv).replace(/\/$/, '');
    if (!req) return 'http://localhost:3000';
    const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http');
    const host = req.get('host') || 'localhost:3000';
    return `${proto}://${host}`.replace(/\/$/, '');
}
/** Robust buffer fetch (https/http) without node-fetch */
function fetchBuffer(urlStr) {
  return new Promise((resolve, reject) => {
    try {
      const u = new URL(urlStr);
      const lib = u.protocol === 'https:' ? https : require('http');
      lib.get(u, (r) => {
        if (r.statusCode && r.statusCode >= 400) return reject(new Error('Fetch failed: ' + r.statusCode));
        const chunks = [];
        r.on('data', (c) => chunks.push(c));
        r.on('end', () => resolve(Buffer.concat(chunks)));
      }).on('error', reject);
    } catch (e) { reject(e); }
  });
}

function safeFileName(name) {
  return String(name || 'file').replace(/[^a-z0-9_-]+/gi, '_').slice(0, 120);
}

function wrapText(font, text, fontSize, maxWidth) {
  const words = String(text || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let line = '';
  for (const w of words) {
    const test = line ? (line + ' ' + w) : w;
    const width = font.widthOfTextAtSize(test, fontSize);
    if (width <= maxWidth) {
      line = test;
    } else {
      if (line) lines.push(line);
      // if a single word is too long, hard-split
      if (font.widthOfTextAtSize(w, fontSize) > maxWidth) {
        let chunk = '';
        for (const ch of w) {
          const t2 = chunk + ch;
          if (font.widthOfTextAtSize(t2, fontSize) <= maxWidth) chunk = t2;
          else { lines.push(chunk); chunk = ch; }
        }
        line = chunk;
      } else {
        line = w;
      }
    }
  }
  if (line) lines.push(line);
  return lines;
}

function fmtDateEn(d) {
  if (!d) return '';
  try {
    const dt = new Date(d);
    return dt.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: '2-digit' });
  } catch { return ''; }
}

/** Create one certificate page as PDF buffer (A4 landscape) using pdf-lib */

/**
 * Create one certificate page as PDF buffer (16:9 landscape) using Puppeteer (HTML/CSS glass design).
 * - Black "glass" modern look
 * - Safe padding so nothing goes outside page
 * - Smaller stamp, signature lower
 */
async function createCertificatePdfBuffer({ settings, article, slug, baseUrl, authorName }) {
  const SITE_NAME = settings?.journalTitle || 'The Global Science';
  const SITE_URL = (settings?.siteUrl || baseUrl || 'https://theglobalscience.org').replace(/\/$/, '');
  const LOGO_URL = (settings?.logoUrl || process.env.SITE_LOGO_URL || '').trim();

  const issnOnline = settings?.issnOnline || 'Pending';
  const publisher = settings?.publisher || SITE_NAME;

  const doi = (article?.doi || '').trim();
  const section = (article?.section || 'Research Article').trim();
  const pages = (article?.pages || '').trim();
  const volume = article?.volume ? String(article.volume) : '';
  const issue = article?.issue ? String(article.issue) : '';
  const year = article?.year ? String(article.year) : (article?.publicationDate ? String(new Date(article.publicationDate).getFullYear()) : '');
  const publishedAt = article?.publishedAt || article?.publicationDate || article?.createdAt || '';
  const receivedAt = article?.receivedAt || '';
  const acceptedAt = article?.acceptedAt || '';

  const verifyUrl = `${SITE_URL}/article.html?slug=${encodeURIComponent(slug)}`;
  const CERT_ID = `TGS-${String(article?._id || '').slice(-8).toUpperCase()}-${String(authorName || '').replace(/\s+/g,'').slice(0,6).toUpperCase() || 'AUTH'}`;

  const STAMP_IMG_URL = (process.env.STAMP_IMAGE_URL || '').trim();
  const SIGNATURE_IMG_URL = (process.env.SIGNATURE_IMAGE_URL || '').trim();
  const SIGNATORY_NAME = (process.env.SIGNATORY_NAME || 'Dr. Jozheff Matthev').trim();
  const SIGNATORY_TITLE = (process.env.SIGNATORY_TITLE || 'Editor-in-Chief, The Global Science').trim();

  function escHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function guessMime(u) {
    const s = String(u || '').toLowerCase();
    if (s.endsWith('.svg')) return 'image/svg+xml';
    if (s.endsWith('.png')) return 'image/png';
    if (s.endsWith('.jpg') || s.endsWith('.jpeg')) return 'image/jpeg';
    if (s.endsWith('.webp')) return 'image/webp';
    return 'application/octet-stream';
  }

  async function toDataUri(url) {
    if (!url) return '';
    try {
      const buf = await fetchBuffer(url);
      const mime = guessMime(url);
      return `data:${mime};base64,${buf.toString('base64')}`;
    } catch {
      // fallback to remote url (may still work if network allowed)
      return url;
    }
  }

  const logoSrc = await toDataUri(LOGO_URL);
  const stampSrc = await toDataUri(STAMP_IMG_URL);
  const signSrc = await toDataUri(SIGNATURE_IMG_URL);

  const articleTitle = (article?.title || '').trim();
  const recipient = (authorName || article?.author || 'Author').trim();

  const fmt = (d) => {
    try {
      if (!d) return '—';
      const dt = new Date(d);
      if (Number.isNaN(dt.getTime())) return '—';
      return dt.toLocaleDateString('en-US', { year:'numeric', month:'long', day:'2-digit' });
    } catch { return '—'; }
  };

  const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Certificate</title>
<style>
  @page { size: 13.333in 7.5in; margin: 0; }
  html, body { margin:0; padding:0; background:#05070c; }
  * { box-sizing: border-box; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; color: #eaf0ff; }

  .page {
    width: 13.333in; height: 7.5in;
    position: relative;
    overflow: hidden;
    background: radial-gradient(1200px 700px at 20% 10%, rgba(99,102,241,.26), rgba(0,0,0,0)),
                radial-gradient(900px 600px at 90% 80%, rgba(217,70,239,.18), rgba(0,0,0,0)),
                linear-gradient(180deg, #04060b 0%, #070a12 60%, #05070c 100%);
  }

  /* Subtle grid */
  .grid {
    position:absolute; inset:0;
    background-image:
      linear-gradient(to right, rgba(255,255,255,.05) 1px, transparent 1px),
      linear-gradient(to bottom, rgba(255,255,255,.05) 1px, transparent 1px);
    background-size: 46px 46px;
    opacity: .08;
    pointer-events:none;
  }

  /* Glass card */
  .card {
    position:absolute;
    inset: 28px;
    border-radius: 22px;
    background: rgba(12, 16, 28, 0.55);
    border: 1px solid rgba(148,163,184,.22);
    box-shadow: 0 30px 80px rgba(0,0,0,.55);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    padding: 30px 34px;
  }

  .accent {
    position:absolute; left: 28px; top: 28px; right: 28px; height: 10px;
    border-radius: 999px;
    background: linear-gradient(90deg, rgba(99,102,241,.95), rgba(217,70,239,.9));
    box-shadow: 0 14px 40px rgba(99,102,241,.18);
    opacity: .9;
  }

  .top {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap: 16px;
    margin-top: 8px;
  }

  .brand { display:flex; align-items:center; gap: 14px; }
  .logo {
    width: 54px; height: 54px; border-radius: 14px;
    background: rgba(255,255,255,.06);
    border: 1px solid rgba(148,163,184,.25);
    display:flex; align-items:center; justify-content:center;
    overflow:hidden;
  }
  .logo img { width: 100%; height: 100%; object-fit: contain; }

  .brandTitle { font-weight: 800; letter-spacing: .2px; font-size: 18px; }
  .brandSub { color: rgba(226,232,240,.75); font-size: 12px; margin-top: 2px; }

  .pill {
    padding: 10px 14px;
    border-radius: 999px;
    border: 1px solid rgba(99,102,241,.30);
    background: rgba(99,102,241,.12);
    color: rgba(224,231,255,.95);
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    white-space: nowrap;
  }

  .title {
    text-align:center;
    margin-top: 18px;
  }
  .title h1 {
    margin:0;
    font-size: 44px;
    letter-spacing: .4px;
    font-weight: 900;
  }
  .title p {
    margin: 8px 0 0;
    color: rgba(203,213,225,.80);
    font-size: 13px;
    line-height: 1.45;
  }

  .recipient {
    margin-top: 18px;
    text-align:center;
  }
  .recipient .label {
    font-size: 12px;
    color: rgba(148,163,184,.95);
    text-transform: uppercase;
    letter-spacing: 1.2px;
  }
  .recipient .name {
    margin-top: 6px;
    font-size: 38px;
    font-weight: 900;
    letter-spacing: .3px;
    background: linear-gradient(90deg, #e2e8f0, #c7d2fe);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }

  .articleBox {
    margin-top: 14px;
    padding: 16px 18px;
    border-radius: 16px;
    border: 1px solid rgba(148,163,184,.22);
    background: rgba(2,6,23,.38);
  }
  .articleBox .k {
    font-size: 11px;
    color: rgba(148,163,184,.95);
    text-transform: uppercase;
    letter-spacing: 1.1px;
    margin-bottom: 8px;
  }
  .articleBox .v {
    font-size: 16px;
    font-weight: 800;
    line-height: 1.25;
    color: rgba(241,245,249,.97);
    max-height: 44px;
    overflow: hidden;
  }

  .grid3 {
    margin-top: 14px;
    display:grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 10px;
  }
  .mini {
    padding: 12px 14px;
    border-radius: 14px;
    border: 1px solid rgba(148,163,184,.18);
    background: rgba(15,23,42,.35);
  }
  .mini .k {
    font-size: 10.5px;
    color: rgba(148,163,184,.92);
    text-transform: uppercase;
    letter-spacing: 1.1px;
  }
  .mini .v {
    margin-top: 6px;
    font-size: 13px;
    font-weight: 800;
    color: rgba(226,232,240,.95);
    line-height: 1.2;
    max-height: 32px;
    overflow:hidden;
  }

  .bottom {
    position:absolute;
    left: 62px; right: 62px;
    bottom: 40px;
    display:flex;
    justify-content:space-between;
    align-items:flex-end;
    gap: 18px;
  }

  .stampWrap { display:flex; align-items:flex-end; gap: 12px; }
  .stamp {
    width: 112px; height: 112px;
    opacity: .9;
    transform: rotate(-10deg);
    filter: drop-shadow(0 10px 28px rgba(0,0,0,.35));
  }
  .stampText {
    font-size: 11px;
    color: rgba(203,213,225,.78);
    line-height: 1.35;
    max-width: 320px;
  }
  .stampText b { color: rgba(241,245,249,.95); }

  .sign {
    text-align:right;
    min-width: 320px;
  }
  .sigImg {
    width: 240px;
    opacity: .92;
    margin-left:auto;
    transform: translateY(8px); /* signature lower */
  }
  .line {
    margin-top: 12px;
    border-top: 1px solid rgba(148,163,184,.35);
    padding-top: 8px;
    font-size: 12px;
    color: rgba(203,213,225,.82);
    line-height: 1.25;
  }
  .line strong { color: rgba(241,245,249,.98); }
  .verify {
    margin-top: 6px;
    font-size: 11px;
    color: rgba(148,163,184,.95);
  }
  .code {
    display:inline-block;
    padding: 2px 8px;
    border-radius: 999px;
    border: 1px solid rgba(99,102,241,.35);
    background: rgba(99,102,241,.12);
    color: rgba(224,231,255,.96);
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 10.5px;
    letter-spacing: .3px;
  }

  /* watermark stamp in center */
  .wm {
    position:absolute; inset:0;
    display:flex; align-items:center; justify-content:center;
    pointer-events:none;
    opacity: .06;
    transform: rotate(-14deg);
  }
  .wm img{ width: 420px; max-width: 52%; }

</style>
</head>
<body>
  <div class="page">
    <div class="grid"></div>
    ${stampSrc ? `<div class="wm"><img src="${stampSrc}" alt="wm"></div>` : ``}

    <div class="card">
      <div class="accent"></div>

      <div class="top">
        <div class="brand">
          <div class="logo">${logoSrc ? `<img src="${logoSrc}" alt="logo">` : ``}</div>
          <div>
            <div class="brandTitle">${escHtml(SITE_NAME)}</div>
            <div class="brandSub">${escHtml(SITE_URL.replace(/^https?:\/\//,''))} • ISSN (Online): ${escHtml(issnOnline)}</div>
          </div>
        </div>
        <div class="pill">Certificate</div>
      </div>

      <div class="title">
        <h1>Certificate of Publication</h1>
        <p>This certificate confirms successful peer review and publication in the official journal archive.</p>
      </div>

      <div class="recipient">
        <div class="label">Presented to</div>
        <div class="name">${escHtml(recipient)}</div>
      </div>

      <div class="articleBox">
        <div class="k">Published article</div>
        <div class="v">${escHtml(articleTitle || '—')}</div>
      </div>

      <div class="grid3">
        <div class="mini">
          <div class="k">Issue</div>
          <div class="v">${escHtml((volume && issue && year) ? `Vol. ${volume} • No. ${issue} • ${year}` : (year || '—'))}</div>
        </div>
        <div class="mini">
          <div class="k">DOI / Section</div>
          <div class="v">${escHtml(doi || '—')} ${doi ? '•' : ''} ${escHtml(section)}</div>
        </div>
        <div class="mini">
          <div class="k">Dates</div>
          <div class="v">R: ${escHtml(fmt(receivedAt))} • A: ${escHtml(fmt(acceptedAt))} • P: ${escHtml(fmt(publishedAt))}</div>
        </div>
      </div>

      <div class="grid3" style="margin-top:10px;">
        <div class="mini">
          <div class="k">Publisher</div>
          <div class="v">${escHtml(publisher)}</div>
        </div>
        <div class="mini">
          <div class="k">Pages / License</div>
          <div class="v">${escHtml(pages || '—')} • ${escHtml(article?.license || settings?.defaultLicense || 'CC BY 4.0')}</div>
        </div>
        <div class="mini">
          <div class="k">Verification</div>
          <div class="v" style="font-size:12px; font-weight:800;">${escHtml(verifyUrl.replace(/^https?:\/\//,''))}</div>
        </div>
      </div>

      <div class="bottom">
        <div class="stampWrap">
          ${stampSrc ? `<img class="stamp" src="${stampSrc}" alt="stamp">` : ``}
          <div class="stampText">
            <b>Certificate ID:</b> <span class="code">${escHtml(CERT_ID)}</span><br>
            <b>Official seal</b> for archive verification.
          </div>
        </div>

        <div class="sign">
          ${signSrc ? `<img class="sigImg" src="${signSrc}" alt="signature">` : ``}
          <div class="line">
            <strong>${escHtml(SIGNATORY_NAME)}</strong><br>
            ${escHtml(SIGNATORY_TITLE)}
          </div>
          <div class="verify">Verify: <span class="code">${escHtml(CERT_ID)}</span></div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;

  // Generate PDF via Puppeteer
  const browser = await puppeteer.launch({
    headless: 'new',
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
    ignoreHTTPSErrors: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--no-zygote',
      '--single-process'
    ]
  });

  try {
    const page = await browser.newPage();
    page.setDefaultNavigationTimeout(45000);
    page.setDefaultTimeout(45000);
    await page.setContent(html, { waitUntil: 'load', timeout: 45000 });

    const pdfBuffer = await page.pdf({
      printBackground: true,
      width: '13.333in',
      height: '7.5in',
      margin: { top: '0in', right: '0in', bottom: '0in', left: '0in' }
    });

    return Buffer.from(pdfBuffer);
  } finally {
    await browser.close();
  }
}
/** Merge base PDF buffer + certificate pages for each author */
async function appendCertificatesToPdfBuffer(basePdfBuffer, { settings, article, slug, baseUrl }) {
  if (!PDFDocument) throw new Error('pdf-lib not installed');
  const outDoc = await PDFDocument.load(basePdfBuffer);
  const authorsArr = (article.authors && article.authors.length) ? article.authors : [{ name: article.author || 'Author' }];
  for (const a of authorsArr) {
    const certBuf = await createCertificatePdfBuffer({ settings, article, slug, baseUrl, authorName: a?.name || article.author || 'Author' });
    const certDoc = await PDFDocument.load(certBuf);
    const certPages = await outDoc.copyPages(certDoc, certDoc.getPageIndices());
    certPages.forEach(p => outDoc.addPage(p));
  }
  const merged = await outDoc.save();
  return Buffer.from(merged);
}


// Generate sitemap (also returns XML string)
async function generateSitemap(baseUrl) {
    try {
        const articles = await Article.find({}, 'slug updatedAt').sort({ createdAt: -1 });

        const base = (baseUrl && String(baseUrl).trim()) ? String(baseUrl).replace(/\/$/, '') : (process.env.BASE_URL || 'http://localhost:3000');
        
        const urlset = {
            $: {
                xmlns: 'http://www.sitemaps.org/schemas/sitemap/0.9'
            },
            url: [
                {
                    loc: `${base}/`,
                    lastmod: new Date().toISOString().split('T')[0],
                    changefreq: 'daily',
                    priority: '1.0'
                },
                {
                    loc: `${base}/articles.html`,
                    lastmod: new Date().toISOString().split('T')[0],
                    changefreq: 'daily',
                    priority: '0.8'
                },
                {
                    loc: `${base}/current-issue.html`,
                    lastmod: new Date().toISOString().split('T')[0],
                    changefreq: 'daily',
                    priority: '0.8'
                },
                {
                    loc: `${base}/archives.html`,
                    lastmod: new Date().toISOString().split('T')[0],
                    changefreq: 'weekly',
                    priority: '0.7'
                },
                {
                    loc: `${base}/submit.html`,
                    changefreq: 'weekly',
                    priority: '0.6'
                },
                {
                    loc: `${base}/editorial-board.html`,
                    changefreq: 'monthly',
                    priority: '0.5'
                },
                {
                    loc: `${base}/author-guidelines.html`,
                    changefreq: 'monthly',
                    priority: '0.5'
                },
                {
                    loc: `${base}/publication-ethics.html`,
                    changefreq: 'monthly',
                    priority: '0.5'
                },
                {
                    loc: `${base}/about.html`,
                    changefreq: 'monthly',
                    priority: '0.5'
                },
                {
                    loc: `${base}/contact.html`,
                    changefreq: 'monthly',
                    priority: '0.5'
                }
            ]
        };

        articles.forEach(article => {
            urlset.url.push({
                loc: `${base}/article.html?slug=${article.slug}`,
                lastmod: article.updatedAt.toISOString().split('T')[0],
                changefreq: 'weekly',
                priority: '0.7'
            });
        });

        const builder = new xml2js.Builder();
        const xml = builder.buildObject({ urlset });
        
        fs.writeFileSync(path.join(__dirname, 'public', 'sitemap.xml'), xml);
        console.log('Sitemap generated successfully');
        return xml;
    } catch (error) {
        console.error('Error generating sitemap:', error);
        return null;
    }
}

// Generate robots.txt (also returns text)
function generateRobotsTxt(baseUrl) {
    const base = (baseUrl && String(baseUrl).trim()) ? String(baseUrl).replace(/\/$/, '') : (process.env.BASE_URL || 'http://localhost:3000');
    const robotsTxt = `User-agent: *
Allow: /
Disallow: /admin.html
Disallow: /api/admin/

Sitemap: ${base}/sitemap.xml
`;
    fs.writeFileSync(path.join(__dirname, 'public', 'robots.txt'), robotsTxt);
    return robotsTxt;
}

// API Routes

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (username === process.env.ADMIN_USERNAME && 
            password === process.env.ADMIN_PASSWORD) {
            
            const token = jwt.sign(
                { username },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            res.json({ token });

        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin token verification (helps admin.html to avoid stale token 401)
app.get('/api/admin/verify', authenticateAdmin, (req, res) => {
    res.json({ ok: true });
});

// ---- Journal settings (public)
app.get('/api/journal/settings', async (req, res) => {
    try {
        const settings = await ensureJournalSettings();
        res.json(settings);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ---- Journal settings (admin)
app.put('/api/admin/journal/settings', authenticateAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        const settings = await ensureJournalSettings();
        const updated = await JournalSettings.findByIdAndUpdate(
            settings._id,
            {
                journalTitle: sanitizeHtml(body.journalTitle || settings.journalTitle),
                issnOnline: sanitizeHtml(body.issnOnline || settings.issnOnline),
                issnPrint: sanitizeHtml(body.issnPrint || settings.issnPrint),
                publisher: sanitizeHtml(body.publisher || settings.publisher),
                scope: sanitizeHtml(body.scope || settings.scope),
                country: sanitizeHtml(body.country || settings.country),
                contactEmail: sanitizeHtml(body.contactEmail || settings.contactEmail),
                defaultLicense: sanitizeHtml(body.defaultLicense || settings.defaultLicense),
                updatedAt: new Date()
            },
            { new: true }
        );
        res.json(updated);
    } catch (e) {
        res.status(500).json({ error: 'Update failed' });
    }
});

// ---- Issues (admin CRUD)
app.post('/api/admin/issues', authenticateAdmin, async (req, res) => {
    try {
        const { volume, number, year, title, description, coverImage, status, publishedAt } = req.body;
        const issue = await Issue.create({
            volume: parseInt(volume),
            number: parseInt(number),
            year: parseInt(year),
            title: sanitizeHtml(title || ''),
            description: sanitizeHtml(description || ''),
            coverImage: sanitizeHtml(coverImage || ''),
            status: status === 'published' ? 'published' : 'draft',
            publishedAt: publishedAt ? new Date(publishedAt) : (status === 'published' ? new Date() : undefined)
        });
        res.json({ success: true, issue });
    } catch (e) {
        res.status(400).json({ error: e?.message || 'Create failed' });
    }
});

app.put('/api/admin/issues/:id', authenticateAdmin, async (req, res) => {
    try {
        const body = req.body || {};
        const upd = {
            volume: body.volume != null ? parseInt(body.volume) : undefined,
            number: body.number != null ? parseInt(body.number) : undefined,
            year: body.year != null ? parseInt(body.year) : undefined,
            title: body.title != null ? sanitizeHtml(body.title) : undefined,
            description: body.description != null ? sanitizeHtml(body.description) : undefined,
            coverImage: body.coverImage != null ? sanitizeHtml(body.coverImage) : undefined,
            status: body.status != null ? (body.status === 'published' ? 'published' : 'draft') : undefined,
            publishedAt: body.publishedAt != null ? new Date(body.publishedAt) : undefined
        };
        Object.keys(upd).forEach(k => upd[k] === undefined && delete upd[k]);
        const issue = await Issue.findByIdAndUpdate(req.params.id, upd, { new: true });
        if (!issue) return res.status(404).json({ error: 'Issue not found' });
        res.json({ success: true, issue });
    } catch (e) {
        res.status(400).json({ error: e?.message || 'Update failed' });
    }
});

app.delete('/api/admin/issues/:id', authenticateAdmin, async (req, res) => {
    try {
        await Issue.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (e) {
        res.status(400).json({ error: 'Delete failed' });
    }
});

app.get('/api/admin/issues', authenticateAdmin, async (req, res) => {
    try {
        const issues = await Issue.find().sort({ year: -1, volume: -1, number: -1 });
        res.json(issues);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ---- Issues (public)
app.get('/api/issues', async (req, res) => {
    try {
        const { year, volume } = req.query;
        const q = { status: 'published' };
        if (year) q.year = parseInt(year);
        if (volume) q.volume = parseInt(volume);
        const issues = await Issue.find(q).sort({ year: -1, volume: -1, number: -1 });
        res.json(issues);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/issues/current', async (req, res) => {
    try {
        const issue = await Issue.findOne({ status: 'published' }).sort({ year: -1, volume: -1, number: -1 });
        if (!issue) return res.status(404).json({ error: 'No published issues yet' });
        res.json(issue);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/issues/:id', async (req, res) => {
    try {
        const issue = await Issue.findById(req.params.id);
        if (!issue || issue.status !== 'published') return res.status(404).json({ error: 'Issue not found' });
        res.json(issue);
    } catch (e) {
        res.status(404).json({ error: 'Issue not found' });
    }
});

app.get('/api/issues/:id/articles', async (req, res) => {
    try {
        const issue = await Issue.findById(req.params.id);
        if (!issue || issue.status !== 'published') return res.status(404).json({ error: 'Issue not found' });
        const articles = await Article.find({ issueId: issue._id }).sort({ publicationDate: -1 }).select('title slug author publicationDate abstract coverImage volume issue year doi license keywords authors pages section views');
        res.json({ issue, articles });
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ---- Auth (author/reviewer/editor)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name, affiliation, orcid } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
        if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

        const existing = await User.findOne({ email: String(email).toLowerCase().trim() });
        if (existing) return res.status(409).json({ error: 'Email already registered' });

        const passwordHash = await bcrypt.hash(String(password), 10);
        const user = await User.create({
            email: String(email).toLowerCase().trim(),
            passwordHash,
            roles: ['author'],
            profile: {
                name: sanitizeHtml(name || ''),
                affiliation: sanitizeHtml(affiliation || ''),
                orcid: sanitizeHtml(orcid || '')
            }
        });
        const token = signUserToken(user);
        res.json({ token, user: { email: user.email, roles: user.roles, profile: user.profile } });
    } catch (e) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: String(email).toLowerCase().trim() });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const ok = await bcrypt.compare(String(password), user.passwordHash);
        if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
        const token = signUserToken(user);
        res.json({ token, user: { email: user.email, roles: user.roles, profile: user.profile } });
    } catch (e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/auth/me', authenticateUser([]), async (req, res) => {
    try {
        const user = await User.findById(req.user.sub).select('email roles profile');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ---- Submissions (author)
app.post('/api/submissions', authenticateUser(['author']), upload.single('manuscriptPdf'), async (req, res) => {
    try {
        const { title, abstract, keywords, authors, coverLetter } = req.body;
        if (!title) return res.status(400).json({ error: 'Title required' });
        if (!req.file) return res.status(400).json({ error: 'PDF required' });

        // Upload manuscript PDF to Cloudinary
        const pdfResult = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { folder: 'journal/submissions', resource_type: 'raw' },
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
            stream.end(req.file.buffer);
        });

        let authorsArr = [];
        try {
            if (authors) authorsArr = JSON.parse(authors);
        } catch (_) {
            authorsArr = [];
        }
        if (!Array.isArray(authorsArr) || authorsArr.length === 0) {
            const u = await User.findById(req.user.sub);
            authorsArr = [{
                name: sanitizeHtml(u?.profile?.name || ''),
                affiliation: sanitizeHtml(u?.profile?.affiliation || ''),
                orcid: sanitizeHtml(u?.profile?.orcid || ''),
                email: sanitizeHtml(u?.email || '')
            }];
        } else {
            authorsArr = authorsArr.map(a => ({
                name: sanitizeHtml(a?.name || ''),
                affiliation: sanitizeHtml(a?.affiliation || ''),
                orcid: sanitizeHtml(a?.orcid || ''),
                email: sanitizeHtml(a?.email || '')
            }));
        }

        let keywordsArr = [];
        try {
            const parsed = JSON.parse(keywords || '[]');
            if (Array.isArray(parsed)) keywordsArr = parsed.map(k => sanitizeHtml(String(k)));
        } catch (_) {
            keywordsArr = String(keywords || '').split(',').map(s => sanitizeHtml(s.trim())).filter(Boolean);
        }

        const slug = `${generateSlug(title)}-${crypto.randomBytes(3).toString('hex')}`;
        const submission = await Submission.create({
            title: sanitizeHtml(title),
            slug,
            authors: authorsArr,
            abstract: sanitizeHtml(abstract || ''),
            keywords: keywordsArr,
            coverLetter: sanitizeHtml(coverLetter || ''),
            manuscriptPdfUrl: pdfResult.secure_url,
            authorUserId: req.user.sub,
            history: [{ by: req.user.email || 'author', action: 'submitted', note: 'Initial submission' }]
        });
        res.json({ success: true, submission });
    } catch (e) {
        console.error('Submission error:', e);
        res.status(500).json({ error: 'Submission failed' });
    }
});

app.get('/api/author/submissions', authenticateUser(['author']), async (req, res) => {
    try {
        const subs = await Submission.find({ authorUserId: req.user.sub }).sort({ createdAt: -1 });
        res.json(subs);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ---- Editor queue (admin token for simplicity)
app.get('/api/editor/submissions', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        const q = {};
        if (status) q.status = status;
        const subs = await Submission.find(q).sort({ createdAt: -1 });
        res.json(subs);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/editor/submissions/:id/decision', authenticateAdmin, async (req, res) => {
    try {
        const { decision, note } = req.body;
        const sub = await Submission.findById(req.params.id);
        if (!sub) return res.status(404).json({ error: 'Submission not found' });
        const map = { accept: 'accepted', minor: 'revision', major: 'revision', reject: 'rejected' };
        const newStatus = map[decision] || sub.status;
        sub.decision = decision || sub.decision;
        sub.status = newStatus;
        sub.editorNote = sanitizeHtml(note || '');
        sub.updatedAt = new Date();
        sub.history.push({ by: process.env.ADMIN_USERNAME || 'editor', action: `decision:${decision}`, note: sanitizeHtml(note || '') });
        await sub.save();
        res.json({ success: true, submission: sub });
    } catch (e) {
        res.status(500).json({ error: 'Decision failed' });
    }
});

app.post('/api/editor/submissions/:id/schedule', authenticateAdmin, async (req, res) => {
    try {
        const { issueId } = req.body;
        const issue = await Issue.findById(issueId);
        if (!issue) return res.status(404).json({ error: 'Issue not found' });
        const sub = await Submission.findById(req.params.id);
        if (!sub) return res.status(404).json({ error: 'Submission not found' });
        sub.scheduledIssueId = issue._id;
        sub.status = 'scheduled';
        sub.updatedAt = new Date();
        sub.history.push({ by: process.env.ADMIN_USERNAME || 'editor', action: 'scheduled', note: `Scheduled to Vol.${issue.volume} No.${issue.number} (${issue.year})` });
        await sub.save();
        res.json({ success: true, submission: sub });
    } catch (e) {
        res.status(500).json({ error: 'Schedule failed' });
    }
});

app.post('/api/editor/submissions/:id/publish', authenticateAdmin, async (req, res) => {
    try {
        const sub = await Submission.findById(req.params.id);
        if (!sub) return res.status(404).json({ error: 'Submission not found' });
        if (!sub.scheduledIssueId) return res.status(400).json({ error: 'Submission not scheduled to an issue' });
        const issue = await Issue.findById(sub.scheduledIssueId);
        if (!issue) return res.status(404).json({ error: 'Issue not found' });
        const settings = await ensureJournalSettings();

        // Convert Submission -> Article (lightweight published record)
        const slug = generateSlug(sub.title);
        const uniqueSlug = await Article.findOne({ slug }) ? `${slug}-${crypto.randomBytes(3).toString('hex')}` : slug;

        const article = await Article.create({
            title: sub.title,
            slug: uniqueSlug,
            author: sub.authors?.[0]?.name || 'Unknown',
            publicationDate: issue.publishedAt || new Date(),
            abstract: sub.abstract || '',
            introduction: '',
            body: [],
            conclusion: '',
            references: [],
            coverImage: issue.coverImage || '',
            pdfUrl: sub.manuscriptPdfUrl,
            journal: settings.journalTitle,
            issnOnline: settings.issnOnline,
            issueId: issue._id,
            volume: issue.volume,
            issue: issue.number,
            year: issue.year,
            license: settings.defaultLicense,
            keywords: sub.keywords || [],
            authors: sub.authors || [],
            receivedAt: sub.createdAt,
            acceptedAt: new Date(),
            publishedAt: issue.publishedAt || new Date(),
            pages: req.body?.pages ? sanitizeHtml(req.body.pages) : '',
            section: req.body?.section ? sanitizeHtml(req.body.section) : 'Research Article'
        });

        sub.status = 'published';
        sub.updatedAt = new Date();
        sub.history.push({ by: process.env.ADMIN_USERNAME || 'editor', action: 'published', note: `Published as article: ${article.slug}` });
        await sub.save();

        generateSitemap();
        res.json({ success: true, article });
    } catch (e) {
        console.error('Publish error:', e);
        res.status(500).json({ error: 'Publish failed' });
    }
});

// Upload article
app.post('/api/admin/articles', authenticateAdmin, upload.fields([
    { name: 'coverImage', maxCount: 1 },
    { name: 'pdfFile', maxCount: 1 }
]), async (req, res) => {
    try {
        const {
            title,
            author,
            publicationDate,
            abstract,
            introduction,
            body,
            conclusion,
            references,
            issueId,
            keywords,
            authors,
            doi,
            license,
            receivedAt,
            acceptedAt,
            pages,
            section
        } = req.body;
        
        // Upload cover image to Cloudinary
        const coverImageResult = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { folder: 'articles/covers', resource_type: 'image' },
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
            stream.end(req.files['coverImage'][0].buffer);
        });

        // Upload PDF to Cloudinary
        const pdfResult = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { folder: 'articles/pdfs', resource_type: 'raw' },
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
            stream.end(req.files['pdfFile'][0].buffer);
        });

        const slug = generateSlug(title);

        let issueDoc = null;
        if (issueId) {
            issueDoc = await Issue.findById(issueId).catch(() => null);
        }

        const settings = await ensureJournalSettings();

        let authorsArr = [];
        try {
            if (authors) authorsArr = JSON.parse(authors);
        } catch (_) {
            authorsArr = [];
        }
        if (!Array.isArray(authorsArr) || authorsArr.length === 0) {
            // Backward compat
            authorsArr = [{ name: sanitizeHtml(author || ''), affiliation: '', orcid: '', email: '' }];
        } else {
            authorsArr = authorsArr.map(a => ({
                name: sanitizeHtml(a?.name || ''),
                affiliation: sanitizeHtml(a?.affiliation || ''),
                orcid: sanitizeHtml(a?.orcid || ''),
                email: sanitizeHtml(a?.email || '')
            }));
        }

        let keywordsArr = [];
        try {
            if (keywords) {
                const parsed = JSON.parse(keywords);
                if (Array.isArray(parsed)) keywordsArr = parsed.map(k => sanitizeHtml(String(k)));
            }
        } catch (_) {
            // allow comma separated
            if (typeof keywords === 'string') {
                keywordsArr = keywords.split(',').map(s => sanitizeHtml(s.trim())).filter(Boolean);
            }
        }
        
        const article = new Article({
            title: sanitizeHtml(title),
            slug,
            author: sanitizeHtml(author),
            publicationDate: new Date(publicationDate), // <-- Yangi maydon
            abstract: sanitizeHtml(abstract),
            introduction: sanitizeHtml(introduction),
            body: JSON.parse(body).map(section => ({
                heading: sanitizeHtml(section.heading),
                content: sanitizeHtml(section.content)
            })),
            conclusion: sanitizeHtml(conclusion),
            references: JSON.parse(references || '[]').map(ref => sanitizeHtml(ref)),
            coverImage: coverImageResult.secure_url,
            coverImagePublicId: coverImageResult.public_id || '',
            pdfUrl: pdfResult.secure_url,
            pdfPublicId: pdfResult.public_id || '',

            journal: settings.journalTitle,
            issnOnline: settings.issnOnline,
            issueId: issueDoc?._id,
            volume: issueDoc?.volume,
            issue: issueDoc?.number,
            year: issueDoc?.year,
            doi: sanitizeHtml(doi || ''),
            license: sanitizeHtml(license || settings.defaultLicense || 'CC BY 4.0'),
            keywords: keywordsArr,
            authors: authorsArr,
            receivedAt: receivedAt ? new Date(receivedAt) : undefined,
            acceptedAt: acceptedAt ? new Date(acceptedAt) : undefined,
            publishedAt: publicationDate ? new Date(publicationDate) : undefined,
            pages: sanitizeHtml(pages || ''),
            section: sanitizeHtml(section || 'Research Article')
        });

        await article.save();
        
        // Regenerate sitemap
        generateSitemap();
        
        res.json({ 
            success: true, 
            article: {
                id: article._id,
                slug: article.slug
            }
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
// ---- Admin: list articles (for admin panel table)
app.get('/api/admin/articles', authenticateAdmin, async (req, res) => {
    try {
        const q = String(req.query.q || '').trim();
        const filter = {};
        if (q) {
            filter.$or = [
                { title: { $regex: q, $options: 'i' } },
                { author: { $regex: q, $options: 'i' } },
                { abstract: { $regex: q, $options: 'i' } }
            ];
        }
        const articles = await Article.find(filter)
            .sort({ createdAt: -1 })
            .limit(200)
            .select('title slug author publicationDate createdAt updatedAt coverImage pdfUrl generatedPdfUrl volume issue year doi pages section views');
        res.json(articles);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ---- Admin: delete article (also removes cloudinary assets when public_id exists)
app.delete('/api/admin/articles/:id', authenticateAdmin, async (req, res) => {
    try {
        const article = await Article.findById(req.params.id);
        if (!article) return res.status(404).json({ error: 'Article not found' });

        // best-effort cloudinary cleanup
        const tasks = [];
        if (article.coverImagePublicId) {
            tasks.push(cloudinary.uploader.destroy(article.coverImagePublicId, { resource_type: 'image' }).catch(() => null));
        }
        if (article.pdfPublicId) {
            tasks.push(cloudinary.uploader.destroy(article.pdfPublicId, { resource_type: 'raw' }).catch(() => null));
        }
        if (article.generatedPdfPublicId) {
            tasks.push(cloudinary.uploader.destroy(article.generatedPdfPublicId, { resource_type: 'raw' }).catch(() => null));
        }
        await Promise.all(tasks);

        await Article.deleteOne({ _id: article._id });

        // Regenerate sitemap (best effort)
        generateSitemap(getBaseUrl(req)).catch(() => {});
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

});

// Get latest articles
app.get('/api/articles/latest', async (req, res) => {
    try {
        const articles = await Article.find()
            .sort({ createdAt: -1 })
            .limit(6)
            .select('title slug author publicationDate abstract coverImage createdAt volume issue year doi license keywords authors pages section');
        
        res.json(articles);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// List articles (simple query API used by the new journal frontend)
// Supports: ?q=keyword&issueId=<mongoId>
app.get('/api/articles', async (req, res) => {
    try {
        const q = String(req.query.q || '').trim();
        const issueId = String(req.query.issueId || '').trim();

        const filter = {};
        if (issueId) filter.issueId = issueId;
        if (q) {
            filter.$or = [
                { title: { $regex: q, $options: 'i' } },
                { author: { $regex: q, $options: 'i' } },
                { abstract: { $regex: q, $options: 'i' } },
                { keywords: { $elemMatch: { $regex: q, $options: 'i' } } }
            ];
        }

        const articles = await Article.find(filter)
            .sort({ createdAt: -1 })
            .limit(50)
            .select('title slug author publicationDate abstract coverImage createdAt volume issue year doi license keywords authors pages section views issueId');

        res.json(articles);
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get article by slug
app.get('/api/articles/:slug', async (req, res) => {
    try {
        const article = await Article.findOne({ slug: req.params.slug });
        
        if (!article) {
            return res.status(404).json({ error: 'Article not found' });
        }
        
        // Increment views
        article.views += 1;
        await article.save();
        
        res.json(article);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Download / Generate PDF
// Default: generates a branded PDF (cover page + article text) inside the website.
// Use ?original=1 to download the originally uploaded PDF file.
app.get('/api/articles/:slug/pdf', async (req, res) => {
    let article = null;
    try {
        const { slug } = req.params;
        const original = String(req.query.original || '').trim() === '1';
        const includeCertificate = String(req.query.certificate || '').trim() === '1';
        const force = String(req.query.force || '').trim() === '1';

        article = await Article.findOne({ slug });
        if (!article) return res.status(404).json({ error: 'Article not found' });

        // --- Fast path: serve cached generated PDF (branded) when available
        // Use ?force=1 to regenerate.
        if (!original && !includeCertificate && !force && article.generatedPdfUrl) {
            try {
                const url = new URL(article.generatedPdfUrl);
                res.setHeader('Content-Disposition', `attachment; filename="${(article.title || 'article').replace(/[^a-z0-9_-]+/gi, '_')}_TGS.pdf"`);
                res.setHeader('Content-Type', 'application/pdf');
                https.get(url, (r) => {
                    if (r.statusCode && r.statusCode >= 400) {
                        throw new Error('Fetch failed: ' + r.statusCode);
                    }
                    r.pipe(res);
                }).on('error', () => res.status(502).json({ error: 'Failed to fetch cached PDF' }));
                return;
            } catch (e) {
                // fallback to regenerate
            }
        }


        // --- Original PDF proxy (backward compatibility)
        if (original) {
            if (!article.pdfUrl) return res.status(404).json({ error: 'PDF not found' });
            const url = new URL(article.pdfUrl);
            res.setHeader('Content-Disposition', `attachment; filename="${(article.title || 'article').replace(/[^a-z0-9_-]+/gi, '_')}.pdf"`);
            res.setHeader('Content-Type', 'application/pdf');
            https.get(url, (r) => {
                if (r.statusCode && r.statusCode >= 400) {
                    return res.status(502).json({ error: 'Failed to fetch PDF' });
                }
                r.pipe(res);
            }).on('error', () => res.status(502).json({ error: 'Failed to fetch PDF' }));
            return;
        }

        const settings = await ensureJournalSettings();
        const baseUrl = getBaseUrl(req);

        // ---- Site identity (for PDF header/cover)
        const SITE_NAME = settings.journalTitle || 'The Global Science';
        const SITE_URL = (settings.siteUrl || baseUrl || 'https://theglobalscience.org').replace(/\/$/,'');
        const LOGO_URL = (settings.logoUrl || process.env.SITE_LOGO_URL || '').trim();

        // ---- Small helpers
        const esc = (s) => String(s ?? '')
            .replace(/&/g,'&amp;')
            .replace(/</g,'&lt;')
            .replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;')
            .replace(/'/g,'&#39;');

        const fmtDate = (d) => {
            if (!d) return '';
            try {
                const dt = new Date(d);
                return dt.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: '2-digit' });
            } catch { return ''; }
        };


        // ---- Certificate HTML builder (1-page, appended or standalone)
        const buildCertificateHtml = () => {
            const journalTitle = settings.journalTitle || 'The Global Science';
            const issnOnline = settings.issnOnline || 'Pending';
            const publisher = settings.publisher || 'Publisher';
            const articleTitle = article.title || '';
            const authors = (article.authors || []).map(a => a?.name).filter(Boolean).join(', ') || (article.author || '');
            const receivedAt = article.receivedAt || article.submittedAt || '';
            const acceptedAt = article.acceptedAt || '';
            const publishedAt = article.publishedAt || article.publicationDate || article.createdAt || '';
            const doi = article.doi ? article.doi : (article.doiNumber ? article.doiNumber : '');

            return `
              <section class="certPage">
                <div class="certFrame">
                  <div class="certTop">
                    <div class="brand">
                      ${LOGO_URL ? `<img class="brandLogo" src="${esc(LOGO_URL)}" alt="logo" />` : ''}
                      <div class="brandText">
                        <div class="brandName">${esc(journalTitle)}</div>
                        <div class="brandUrl">${esc(SITE_URL.replace(/^https?:\/\//,''))}</div>
                      </div>
                    </div>
                    <div class="certTag">Certificate</div>
                  </div>

                  <div class="certBody">
                    <div class="certTitle">Certificate of Publication</div>
                    <div class="certLead">
                      This is to certify that the following article has been published in
                      <b>${esc(journalTitle)}</b> (ISSN Online: <b>${esc(issnOnline)}</b>).
                    </div>

                    <div class="certCard">
                      <div class="row">
                        <div class="lbl">Article title</div>
                        <div class="val">${esc(articleTitle)}</div>
                      </div>
                      <div class="row">
                        <div class="lbl">Authors</div>
                        <div class="val">${esc(authors || '—')}</div>
                      </div>
                      ${doi ? `<div class="row"><div class="lbl">DOI</div><div class="val">${esc(doi)}</div></div>` : ''}
                      <div class="row grid3">
                        <div>
                          <div class="lbl">Received</div>
                          <div class="val">${esc(fmtDate(receivedAt) || '—')}</div>
                        </div>
                        <div>
                          <div class="lbl">Accepted</div>
                          <div class="val">${esc(fmtDate(acceptedAt) || '—')}</div>
                        </div>
                        <div>
                          <div class="lbl">Published</div>
                          <div class="val">${esc(fmtDate(publishedAt) || '—')}</div>
                        </div>
                      </div>
                    </div>

                    <div class="certFooter">
                      <div class="small">
                        Publisher: <b>${esc(publisher)}</b><br/>
                        Verification: ${esc(SITE_URL)}/article.html?slug=${encodeURIComponent(slug)}
                      </div>
                      <div class="stamp">
                        <div class="stampRing"></div>
                        <div class="stampText">${esc(journalTitle)}</div>
                      </div>
                    </div>
                  </div>
                </div>
              </section>`;
        };

        // Robust buffer fetch (works without node-fetch)
        const fetchBuffer = (urlStr) => new Promise((resolve, reject) => {
            try {
                const u = new URL(urlStr);
                const lib = u.protocol === 'https:' ? https : require('http');
                lib.get(u, (r) => {
                    if (r.statusCode && r.statusCode >= 400) return reject(new Error('Fetch failed'));
                    const chunks = [];
                    r.on('data', (c) => chunks.push(c));
                    r.on('end', () => resolve(Buffer.concat(chunks)));
                }).on('error', reject);
            } catch (e) { reject(e); }
        });

        // --- 1) Build branded front-matter PDF (Cover + About + Article details)
        const buildFrontMatterPdf = async () => {
            const coverImage = article.coverImageUrl || '';
            const doi = article.doi ? article.doi : (article.doiNumber ? article.doiNumber : '');
            const license = article.license || 'Open Access';
            const issue = settings.issue || settings.currentIssue || '';
            const volume = settings.volume || settings.currentVolume || '';

            const authors = (article.authors || []).map(a => a?.name).filter(Boolean).join(', ') || (article.author || '');
            const affiliations = (article.authors || []).map(a => a?.affiliation).filter(Boolean).join(' • ');
            const keywords = (article.keywords || []).join(', ');

            // Simple QR (optional): uses public QR service only if allowed; otherwise text-only.
            const qrUrl = `${SITE_URL}/articles/${encodeURIComponent(slug)}`;

            const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>${esc(article.title || 'Article')}</title>
<style>
  @page { size: A4; margin: 0; }
  html, body { margin:0; padding:0; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; color:#0f172a; background:#fff; }
  .page { width: 210mm; height: 297mm; padding: 18mm 16mm; box-sizing: border-box; position: relative; overflow:hidden; }
  .cover {
    background:
      radial-gradient(1200px 600px at 20% 10%, rgba(59,130,246,.28), rgba(255,255,255,0) 55%),
      radial-gradient(900px 500px at 90% 30%, rgba(168,85,247,.22), rgba(255,255,255,0) 55%),
      linear-gradient(135deg, #0b1220 0%, #0f1a2e 45%, #0b1220 100%);
    color:#e5e7eb;
  }
  .badge { display:inline-flex; align-items:center; gap:8px; padding:8px 12px; border-radius:999px; background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.18); font-size:12px; }
  .brand { display:flex; align-items:center; justify-content:space-between; margin-bottom: 18mm; }
  .brand-left { display:flex; align-items:center; gap:12px; }
  .logo { width: 42px; height:42px; border-radius:10px; background: rgba(255,255,255,.12); display:flex; align-items:center; justify-content:center; overflow:hidden; }
  .logo img { width: 100%; height: 100%; object-fit: cover; }
  .site-name { font-weight:800; letter-spacing:.3px; font-size: 18px; }
  .site-url { font-size:12px; opacity:.85; }
  .title { font-size: 34px; line-height: 1.1; font-weight: 900; margin: 0 0 10px 0; }
  .subtitle { font-size: 14px; opacity: .9; margin: 0 0 14px 0; }
  .meta-grid { display:grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10mm; }
  .card { border-radius: 16px; padding: 12px 14px; background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.16); }
  .k { font-size: 11px; opacity: .75; margin-bottom: 4px; }
  .v { font-size: 13px; font-weight: 700; }
  .cover-image { position:absolute; right:16mm; bottom:18mm; width: 74mm; height: 74mm; border-radius: 18px; overflow:hidden; border: 1px solid rgba(255,255,255,.18); background: rgba(255,255,255,.06); }
  .cover-image img { width:100%; height:100%; object-fit: cover; }
  .footerline { position:absolute; left:16mm; right:16mm; bottom: 12mm; display:flex; justify-content:space-between; font-size:11px; opacity:.85; }
  .page2 {
    background:
      radial-gradient(900px 500px at 10% 10%, rgba(59,130,246,.12), rgba(255,255,255,0) 55%),
      radial-gradient(700px 420px at 85% 20%, rgba(168,85,247,.10), rgba(255,255,255,0) 55%),
      #ffffff;
  }
  .h1 { font-size: 22px; font-weight: 900; margin: 0 0 6px 0; }
  .lead { color: rgba(15,23,42,.75); margin:0 0 16px 0; }
  .info { display:grid; grid-template-columns: 1.15fr .85fr; gap: 12px; margin-top: 8px; }
  .panel { border-radius: 14px; border:1px solid rgba(15,23,42,.10); background: rgba(248,250,252,.85); padding: 12px 14px; }
  .panel h3 { margin:0 0 8px 0; font-size: 13px; letter-spacing:.2px; text-transform: uppercase; color: rgba(15,23,42,.65); }
  .row { display:flex; gap:10px; margin: 8px 0; }
  .pill { display:inline-block; padding:6px 10px; border-radius:999px; background: rgba(59,130,246,.10); color:#1d4ed8; font-weight:700; font-size:12px; }
  .small { font-size:12px; color: rgba(15,23,42,.72); line-height:1.6; }
  .label { font-size: 11px; color: rgba(15,23,42,.55); }
  .value { font-size: 12px; font-weight: 700; color: rgba(15,23,42,.85); }
  .hr { height:1px; background: rgba(15,23,42,.10); margin: 10px 0; }
  .page-break { page-break-before: always; }

  /* Certificate page */
  .certPage { page-break-before: always; padding: 18mm 16mm 18mm; }
  .certFrame { border: 1px solid rgba(15,23,42,.15); border-radius: 18px; overflow:hidden; position:relative; }
  .certFrame:before { content:''; position:absolute; inset:0; background: radial-gradient(900px 420px at 15% 10%, rgba(59,130,246,.12), transparent 60%),
    radial-gradient(700px 380px at 85% 35%, rgba(168,85,247,.12), transparent 60%),
    radial-gradient(850px 420px at 45% 90%, rgba(16,185,129,.10), transparent 60%); pointer-events:none; }
  .certTop { position:relative; display:flex; justify-content:space-between; align-items:center; padding: 14mm 14mm 8mm; background: linear-gradient(90deg, rgba(15,23,42,.94), rgba(30,41,59,.94)); color:#fff; }
  .brand { display:flex; gap:10px; align-items:center; }
  .brandLogo { width:44px; height:44px; object-fit:contain; background: rgba(255,255,255,.10); border-radius: 12px; padding: 8px; }
  .brandName { font-weight: 900; font-size: 16px; letter-spacing:.2px; }
  .brandUrl { font-size: 11px; opacity:.85; margin-top:2px; }
  .certTag { font-size: 11px; font-weight: 800; letter-spacing: .22em; text-transform: uppercase; padding: 8px 10px; border-radius: 999px; background: rgba(255,255,255,.10); border: 1px solid rgba(255,255,255,.14); }
  .certBody { position:relative; padding: 14mm; }
  .certTitle { font-size: 26px; font-weight: 950; letter-spacing:-.02em; }
  .certLead { margin-top: 8px; font-size: 13px; line-height: 1.7; color: rgba(15,23,42,.85); max-width: 520px; }
  .certCard { margin-top: 12mm; padding: 10mm; border-radius: 16px; background: rgba(248,250,252,.82); border: 1px solid rgba(15,23,42,.10); }
  .certCard .row { display:grid; grid-template-columns: 140px 1fr; gap: 10px; padding: 8px 0; border-bottom: 1px dashed rgba(15,23,42,.12); }
  .certCard .row:last-child { border-bottom: none; }
  .certCard .lbl { font-size: 11px; font-weight: 800; letter-spacing:.08em; text-transform: uppercase; color: rgba(15,23,42,.60); }
  .certCard .val { font-size: 13px; font-weight: 700; color: rgba(15,23,42,.88); }
  .certCard .grid3 { grid-template-columns: 1fr 1fr 1fr; }
  .certCard .grid3 > div { border-right: 1px dashed rgba(15,23,42,.12); padding-right: 8px; }
  .certCard .grid3 > div:last-child { border-right: none; padding-right: 0; }
  .certFooter { margin-top: 12mm; display:flex; justify-content:space-between; align-items:flex-end; gap: 16px; }
  .certFooter .small { font-size: 11px; color: rgba(15,23,42,.70); line-height: 1.5; }
  .stamp { width: 130px; height: 130px; position:relative; }
  .stampRing { position:absolute; inset:0; border-radius: 50%; border: 3px solid rgba(59,130,246,.55); box-shadow: inset 0 0 0 6px rgba(168,85,247,.16); transform: rotate(-12deg); }
  .stampText { position:absolute; inset: 22px; border-radius: 50%; display:flex; align-items:center; justify-content:center; text-align:center;
    font-weight: 900; font-size: 10px; color: rgba(15,23,42,.80); background: rgba(255,255,255,.65); border: 1px solid rgba(15,23,42,.10); padding: 10px; transform: rotate(12deg); }

</style>
</head>
<body>
  <section class="page cover">
    <div class="brand">
      <div class="brand-left">
        <div class="logo">${LOGO_URL ? `<img src="${esc(LOGO_URL)}" />` : ''}</div>
        <div>
          <div class="site-name">${esc(SITE_NAME)}</div>
          <div class="site-url">${esc(SITE_URL.replace(/^https?:\/\//,''))}</div>
        </div>
      </div>
      <div class="badge">
        <span>${esc(volume ? `Vol. ${volume}` : 'Vol.')}</span>
        <span>•</span>
        <span>${esc(issue ? `Issue ${issue}` : 'Issue')}</span>
        <span>•</span>
        <span>${esc(fmtDate(article.createdAt || new Date()))}</span>
      </div>
    </div>

    <h1 class="title">${esc(article.title || '')}</h1>
    <p class="subtitle">${authors ? esc(authors) : ''}</p>

    <div class="meta-grid">
      <div class="card"><div class="k">Article ID</div><div class="v mono">${esc(article.slug || slug)}</div></div>
      <div class="card"><div class="k">Access</div><div class="v">${esc(license)}</div></div>
      <div class="card"><div class="k">DOI</div><div class="v">${doi ? esc(doi) : '—'}</div></div>
      <div class="card"><div class="k">Category</div><div class="v">${esc(article.category || article.section || 'Science')}</div></div>
    </div>

    ${coverImage ? `<div class="cover-image"><img src="${esc(coverImage)}" /></div>` : ''}

    <div class="footerline">
      <div>Powered by ${esc(SITE_NAME)}</div>
      <div>${esc(qrUrl)}</div>
    </div>
  </section>

  <section class="page page2 page-break">
    <div class="brand" style="margin-bottom:10mm;">
      <div class="brand-left">
        <div class="logo" style="background:rgba(59,130,246,.10); border:1px solid rgba(59,130,246,.25);">${LOGO_URL ? `<img src="${esc(LOGO_URL)}" />` : ''}</div>
        <div>
          <div class="site-name" style="color:#0f172a;">${esc(SITE_NAME)}</div>
          <div class="site-url" style="color:rgba(15,23,42,.70);">${esc(SITE_URL)}</div>
        </div>
      </div>
      <div class="pill">About & Article Details</div>
    </div>

    <h2 class="h1">About the website</h2>
    <p class="lead small">${esc(settings.aboutText || 'The Global Science is an open-access publishing platform for peer-reviewed articles. This PDF package includes website details and the article metadata, followed by the original manuscript pages.')}</p>

    <div class="info">
      <div class="panel">
        <h3>Article metadata</h3>
        <div class="row"><div style="flex:1;"><div class="label">Title</div><div class="value">${esc(article.title || '')}</div></div></div>
        <div class="row">
          <div style="flex:1;"><div class="label">Authors</div><div class="value">${esc(authors || '—')}</div></div>
        </div>
        ${affiliations ? `<div class="row"><div style="flex:1;"><div class="label">Affiliations</div><div class="value">${esc(affiliations)}</div></div></div>` : ''}
        ${article.abstract ? `<div class="hr"></div><div class="label">Abstract</div><div class="small">${esc(article.abstract)}</div>` : ''}
        ${keywords ? `<div class="hr"></div><div class="label">Keywords</div><div class="small">${esc(keywords)}</div>` : ''}
      </div>

      <div class="panel">
        <h3>Website details</h3>
        <div class="row"><div style="flex:1;"><div class="label">Website</div><div class="value">${esc(SITE_URL)}</div></div></div>
        <div class="row"><div style="flex:1;"><div class="label">Journal title</div><div class="value">${esc(SITE_NAME)}</div></div></div>
        <div class="row"><div style="flex:1;"><div class="label">ISSN (Online)</div><div class="value">${esc(settings.issnOnline || '—')}</div></div></div>
        <div class="row"><div style="flex:1;"><div class="label">ISSN (Print)</div><div class="value">${esc(settings.issnPrint || '—')}</div></div></div>
        <div class="hr"></div>
        <div class="label">Article link</div>
        <div class="small mono">${esc(qrUrl)}</div>
      </div>
    </div>

    <div style="position:absolute; left:16mm; right:16mm; bottom:12mm; display:flex; justify-content:space-between; color:rgba(15,23,42,.60); font-size:11px;">
      <div>${esc(SITE_NAME)} • ${esc(SITE_URL.replace(/^https?:\/\//,''))}</div>
      <div>Package generated: ${esc(fmtDate(new Date()))}</div>
    </div>
  </section>
</body>
</html>`;

            const browser = await puppeteer.launch({
                headless: 'new',
                args: ['--no-sandbox', '--disable-setuid-sandbox']
            });

            try {
                const page = await browser.newPage();
                page.setDefaultNavigationTimeout(45000);
                page.setDefaultTimeout(45000);
                await page.setContent(html, { waitUntil: 'load', timeout: 45000 });
                const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true, margin: { top: '0', bottom: '0', left: '0', right: '0' } });
                return pdfBuffer;
            } finally {
                await browser.close();
            }
        };

        // --- 2) If original PDF exists: merge front-matter + original PDF pages WITH header on every original page
        if (article.pdfUrl) {
            // Ensure pdf-lib is available
            if (!PDFDocument) {
                return res.status(500).json({ error: 'Missing dependency: pdf-lib. Please run: npm i pdf-lib' });
            }

            const [frontBuf, originalBuf, logoBuf] = await Promise.all([
                buildFrontMatterPdf(),
                fetchBuffer(article.pdfUrl),
                LOGO_URL ? fetchBuffer(LOGO_URL).catch(() => null) : Promise.resolve(null)
            ]);

            const frontDoc = await PDFDocument.load(frontBuf);
            const originalDoc = await PDFDocument.load(originalBuf);
            const outDoc = await PDFDocument.create();

            // Copy front pages
            const frontPages = await outDoc.copyPages(frontDoc, frontDoc.getPageIndices());
            frontPages.forEach(p => outDoc.addPage(p));

            // Embed logo (optional)
            let embeddedLogo = null;
            if (logoBuf && logoBuf.length > 8) {
                const isPng = logoBuf.slice(0, 8).toString('hex') === '89504e470d0a1a0a';
                try {
                    embeddedLogo = isPng ? await outDoc.embedPng(logoBuf) : await outDoc.embedJpg(logoBuf);
                } catch { embeddedLogo = null; }
            }

            // Fonts
            const fontBold = await outDoc.embedFont(StandardFonts.HelveticaBold);
            const font = await outDoc.embedFont(StandardFonts.Helvetica);

            const originalPages = await outDoc.copyPages(originalDoc, originalDoc.getPageIndices());
            originalPages.forEach((page) => {
                // Add page first, then draw header on it
                outDoc.addPage(page);

                const { width, height } = page.getSize();

                // Header bar
                const headerH = 38; // points
                page.drawRectangle({
                    x: 0,
                    y: height - headerH,
                    width,
                    height: headerH,
                    color: rgb(0.97, 0.98, 1),
                    opacity: 1,
                });
                // thin line
                page.drawRectangle({
                    x: 0,
                    y: height - headerH,
                    width,
                    height: 1,
                    color: rgb(0.82, 0.86, 0.95)
                });

                const padX = 28;
                const logoSize = 18;

                if (embeddedLogo) {
                    page.drawImage(embeddedLogo, {
                        x: padX,
                        y: height - headerH + (headerH - logoSize) / 2,
                        width: logoSize,
                        height: logoSize
                    });
                }

                const textX = padX + (embeddedLogo ? (logoSize + 10) : 0);
                page.drawText(SITE_NAME, {
                    x: textX,
                    y: height - 24,
                    size: 11,
                    font: fontBold,
                    color: rgb(0.12, 0.16, 0.25)
                });

                page.drawText(SITE_URL.replace(/^https?:\/\//,''), {
                    x: textX,
                    y: height - 36,
                    size: 8.5,
                    font,
                    color: rgb(0.35, 0.4, 0.5)
                });

                // Right side: article slug
                const rightText = (article.slug || slug);
                const rtSize = 8.5;
                const rtWidth = font.widthOfTextAtSize(rightText, rtSize);
                page.drawText(rightText, {
                    x: Math.max(width - padX - rtWidth, textX + 180),
                    y: height - 34,
                    size: rtSize,
                    font,
                    color: rgb(0.35, 0.4, 0.5)
                });
            });

            const outBytes = await outDoc.save();

            res.setHeader('Content-Disposition', `attachment; filename="${(article.title || 'article').replace(/[^a-z0-9_-]+/gi, '_')}_TGS_package.pdf"`);
            res.setHeader('Content-Type', 'application/pdf');
            return res.send(Buffer.from(outBytes));
        }

        // --- 3) Fallback: no original PDF -> render website-branded article content PDF (header/footer already)
        // Existing HTML builder below (kept from previous version, but with slightly richer colors)
        const settings2 = settings;
        const journalTitle = SITE_NAME;
        const issnOnline = settings2.issnOnline || '';
        const issnPrint = settings2.issnPrint || '';

        const authorsHtml = (article.authors && article.authors.length)
            ? article.authors.map(a => `<div class="author">
                <div class="name">${esc(a.name || '')}</div>
                ${a.affiliation ? `<div class="aff">${esc(a.affiliation)}</div>` : ''}
                ${a.email ? `<div class="email">${esc(a.email)}</div>` : ''}
              </div>`).join('')
            : (article.author ? `<div class="author"><div class="name">${esc(article.author)}</div></div>` : '');

        const blocks = Array.isArray(article.blocks) ? article.blocks : [];
        const bodyParts = blocks.map(b => {
            if (!b) return '';
            if (b.type === 'h2') return `<h2>${esc(b.text || '')}</h2>`;
            if (b.type === 'p') return `<p>${esc(b.text || '')}</p>`;
            if (b.type === 'quote') return `<blockquote class="avoid">${esc(b.text || '')}</blockquote>`;
            if (b.type === 'list') return `<ul>${(b.items || []).map(it => `<li>${esc(it)}</li>`).join('')}</ul>`;
            if (b.type === 'image' && b.image?.url) return `<figure class="avoid">
                <img src="${esc(b.image.url)}" alt="image"/>
                ${b.image.caption ? `<figcaption>${esc(b.image.caption)}</figcaption>` : ''}
              </figure>`;
            return '';
        });

        const refsHtml = Array.isArray(article.references) && article.references.length
            ? `<ol>${article.references.map(r => `<li>${esc(r)}</li>`).join('')}</ol>`
            : `<div class="muted">No references provided.</div>`;

        const doi = article.doi ? article.doi : (article.doiNumber ? article.doiNumber : '');
        const license = article.license || 'Open Access';

        const html = `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${esc(article.title || '')}</title>
<style>
  @page { size: A4; margin: 16mm; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; color:#0f172a; }
  .topband { height: 10px; background: linear-gradient(90deg, #3b82f6, #a855f7); border-radius: 999px; margin-bottom: 10px; }
  .header { padding: 10px 0 12px; border-bottom: 1px solid rgba(15,23,42,.10); }
  .title { font-size: 22px; font-weight: 900; margin: 8px 0 6px; }
  .subtitle { color: rgba(15,23,42,.72); margin:0 0 10px; }
  .meta { display:flex; flex-wrap:wrap; gap:8px; margin-top: 10px; }
  .chip { display:inline-block; padding:6px 10px; border-radius:999px; background: rgba(59,130,246,.10); color:#1d4ed8; font-weight: 800; font-size: 11px; }
  .grid { display:grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 12px; }
  .box { border: 1px solid rgba(15,23,42,.10); border-radius: 14px; padding: 10px 12px; background: rgba(248,250,252,.85); }
  .authors { display:flex; flex-direction:column; gap:8px; }
  .author .name { font-weight: 900; }
  .author .aff, .author .email { font-size: 12px; color: rgba(15,23,42,.70); }
  h2 { font-size: 15px; margin: 16px 0 8px; border-left: 4px solid #3b82f6; padding-left: 10px; }
  p, li { font-size: 12.2px; line-height: 1.68; color: rgba(15,23,42,.88); }
  figure { margin: 12px 0; }
  img { max-width: 100%; border-radius: 12px; border: 1px solid rgba(15,23,42,.10); }
  figcaption { font-size: 11px; color: rgba(15,23,42,.60); margin-top: 6px; }
  blockquote { border-left: 4px solid #a855f7; background: rgba(168,85,247,.08); padding: 10px 12px; border-radius: 12px; color: rgba(15,23,42,.85); }
  .muted { color: rgba(15,23,42,.55); }
  .avoid { break-inside: avoid; page-break-inside: avoid; }
</style>
</head>
<body>
  <div class="topband"></div>
  <header class="header">
    <div class="muted" style="font-size:12px; font-weight:800;">${esc(journalTitle)} • ${esc(SITE_URL.replace(/^https?:\/\//,''))}</div>
    <div class="title">${esc(article.title || '')}</div>
    <div class="subtitle">${esc(article.subtitle || '')}</div>
    <div class="meta">
      <div class="chip">${esc(license)}</div>
      ${article.category ? `<div class="chip">${esc(article.category)}</div>` : ''}
      ${doi ? `<div class="chip">DOI: ${esc(doi)}</div>` : ''}
    </div>
    <div class="grid">
      <div class="box">
        <div class="muted" style="font-size:11px; font-weight:800; margin-bottom:6px;">Authors</div>
        <div class="authors">${authorsHtml || `<div class="muted">—</div>`}</div>
      </div>
      <div class="box">
        <div class="muted" style="font-size:11px; font-weight:800; margin-bottom:6px;">Abstract</div>
        <div style="font-size:12px; line-height:1.65; color: rgba(15,23,42,.86);">${esc(article.abstract || '—')}</div>
      </div>
    </div>
  </header>

  <main>
    ${bodyParts.join('\n')}
    <section class="avoid" style="margin-top:14px;">
      <h2>References</h2>
      ${refsHtml}
    </section>
  </main>
    
</body>
</html>`;

        const browser = await puppeteer.launch({
            headless: 'new',
            executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
            ignoreHTTPSErrors: true,
            args: [
              '--no-sandbox',
              '--disable-setuid-sandbox',
              '--disable-dev-shm-usage',
              '--no-zygote',
              '--single-process'
            ]
        });

        try {
            const page = await browser.newPage();
            page.setDefaultNavigationTimeout(45000);
                page.setDefaultTimeout(45000);
                await page.setContent(html, { waitUntil: 'load', timeout: 45000 });

            const pdfBuffer = await page.pdf({
                format: 'A4',
                printBackground: true,
                displayHeaderFooter: true,
                headerTemplate: `
                    <div style="width:100%; padding:0 16mm; height:16mm; display:flex; justify-content:space-between; align-items:flex-end; font-size:9px; line-height:1; color:rgba(15,23,42,.72); border-bottom:1px solid rgba(15,23,42,.12);">
                      <div style="font-weight:800; letter-spacing:.2px;">${esc(SITE_NAME)}</div>
                      <div>${esc(SITE_URL.replace(/^https?:\/\//,''))}</div>
                    </div>
                `,
                footerTemplate: `
                    <div style="width:100%; padding:0 16mm; height:14mm; display:flex; justify-content:space-between; align-items:flex-start; font-size:9px; line-height:1; color:rgba(15,23,42,.72); border-top:1px solid rgba(15,23,42,.12);">
                      <div style="padding-top:2mm;">ISSN (Online): ${esc(issnOnline)}</div>
                      <div style="padding-top:2mm;">Page <span class="pageNumber"></span> / <span class="totalPages"></span></div>
                    </div>
                `,
                margin: { top: '34mm', bottom: '24mm', left: '16mm', right: '16mm' }
            });

            res.setHeader('Content-Disposition', `attachment; filename="${(article.title || 'article').replace(/[^a-z0-9_-]+/gi, '_')}_TGS.pdf"`);
            res.setHeader('Content-Type', 'application/pdf');
            let out = pdfBuffer;
            if (includeCertificate) {
              try {
                out = await appendCertificatesToPdfBuffer(pdfBuffer, { settings, article, slug, baseUrl });
              } catch (e) {
                console.error('Append certificate failed:', e);
              }
            }

            // Cache generated branded PDF (without certificate) to avoid "generation failed" on low-resource hosts.
            if (!includeCertificate) {
              try {
                const uploaded = await uploadBufferToCloudinary(out, { folder: 'tgs/generated', filename: `${article.slug}_TGS.pdf` });
                if (uploaded?.secure_url) {
                  article.generatedPdfUrl = uploaded.secure_url;
                  article.generatedPdfPublicId = uploaded.public_id || '';
                  article.generatedPdfUpdatedAt = new Date();
                  await article.save().catch(() => {});
                }
              } catch (e) {
                console.warn('Generated PDF cache upload failed:', e?.message || e);
              }
            }

            res.send(out);
        } finally {
            await browser.close();
        }
    } catch (e) {
        console.error('PDF generate error:', e);

        // Fallback: if branded generation fails (Puppeteer/Chromium issues), serve the original uploaded PDF.
        try {
            if (article && article.pdfUrl) {
                const url = new URL(article.pdfUrl);
                res.setHeader('Content-Disposition', `attachment; filename="${(article.title || 'article').replace(/[^a-z0-9_-]+/gi, '_')}.pdf"`);
                res.setHeader('Content-Type', 'application/pdf');
                https.get(url, (r) => {
                    if (r.statusCode && r.statusCode >= 400) {
                        return res.status(502).json({ error: 'Failed to fetch PDF' });
                    }
                    r.pipe(res);
                }).on('error', () => res.status(502).json({ error: 'Failed to fetch PDF' }));
                return;
            }
        } catch (_) {}

        res.status(500).json({ error: 'PDF generation failed' });
    }
});


// Standalone certificate PDF
// - default: returns ONE certificate page (author index 0)
// - ?author=1 -> certificate for that author index
// - ?all=1 -> multi-page PDF (one page per author)
app.get('/api/articles/:slug/certificate.pdf', async (req, res) => {
  try {
    const { slug } = req.params;
    const article = await Article.findOne({ slug });
    if (!article) return res.status(404).json({ error: 'Article not found' });

    const settings = await ensureJournalSettings();
    const baseUrl = getBaseUrl(req);

    if (!PDFDocument) {
      return res.status(500).json({ error: 'pdf-lib not installed on server. Run: npm i pdf-lib' });
    }

    const authorsArr = (article.authors && article.authors.length) ? article.authors : [{ name: article.author || 'Author' }];

    const wantAll = String(req.query.all || '').trim() === '1';
    const authorIdx = Number.isFinite(Number(req.query.author)) ? parseInt(req.query.author, 10) : 0;

    // Multi-page combined certificate PDF (all authors)
    if (wantAll) {
      const outDoc = await PDFDocument.create();
      for (const a of authorsArr) {
        const buf = await createCertificatePdfBuffer({ settings, article, slug, baseUrl, authorName: a?.name || article.author || 'Author' });
        const certDoc = await PDFDocument.load(buf);
        const pages = await outDoc.copyPages(certDoc, certDoc.getPageIndices());
        pages.forEach(p => outDoc.addPage(p));
      }
      const bytes = await outDoc.save();
      const outBuf = Buffer.from(bytes);
      res.setHeader('Content-Disposition', `attachment; filename="${safeFileName(article.title)}_Certificates.pdf"`);
      res.setHeader('Content-Type', 'application/pdf');
      return res.send(outBuf);
    }

    const a = authorsArr[Math.max(0, Math.min(authorIdx, authorsArr.length - 1))];
    const authorName = a?.name || article.author || 'Author';

    const pdfBuffer = await createCertificatePdfBuffer({ settings, article, slug, baseUrl, authorName });

    res.setHeader('Content-Disposition', `attachment; filename="${safeFileName(article.title)}_${safeFileName(authorName)}_Certificate.pdf"`);
    res.setHeader('Content-Type', 'application/pdf');
    res.send(pdfBuffer);
  } catch (e) {
    console.error('Certificate generate error:', e);
    res.status(500).json({ error: 'Certificate generation failed' });
  }
});



// Search articles
app.get('/api/articles/search/:query', async (req, res) => {
    try {
        const query = req.params.query;
        
        const articles = await Article.find({
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { author: { $regex: query, $options: 'i' } },
                { abstract: { $regex: query, $options: 'i' } }
            ]
        })
        .sort({ createdAt: -1 })
        .select('title slug author publicationDate abstract coverImage volume issue year doi license keywords authors pages section views');
        
        res.json(articles);
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// Paginated articles
app.get('/api/articles/page/:page', async (req, res) => {
    try {
        const page = parseInt(req.params.page) || 1;
        const limit = 12;
        const skip = (page - 1) * limit;
        
        const [articles, total] = await Promise.all([
            Article.find()
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .select('title slug author publicationDate abstract coverImage volume issue year doi license keywords authors pages section views'),
            Article.countDocuments()
        ]);
        
        res.json({
            articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalArticles: total
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Submit rating
app.post('/api/articles/:id/rate', async (req, res) => {
    try {
        const { rating } = req.body;
        const userIp = req.ip;
        
        // Check if user already rated
        const existingRating = await Rating.findOne({
            articleId: req.params.id,
            userIp
        });
        
        if (existingRating) {
            return res.status(400).json({ error: 'You have already rated this article' });
        }
        
        const newRating = new Rating({
            articleId: req.params.id,
            rating: Math.min(5, Math.max(1, parseInt(rating))),
            userIp
        });
        
        await newRating.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Rating failed' });
    }
});

// Submit comment
app.post('/api/articles/:id/comment', async (req, res) => {
    try {
        const { name, comment } = req.body;
        const userIp = req.ip;
        
        // Rate limiting per IP
        const recentComments = await Comment.countDocuments({
            userIp,
            createdAt: { $gt: new Date(Date.now() - 5 * 60 * 1000) } // Last 5 minutes
        });
        
        if (recentComments >= 3) {
            return res.status(429).json({ error: 'Too many comments. Please wait 5 minutes.' });
        }
        
        const newComment = new Comment({
            articleId: req.params.id,
            name: sanitizeHtml(name || 'Anonymous'),
            comment: sanitizeHtml(comment),
            userIp
        });
        
        await newComment.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Comment failed' });
    }
});

// Get comments
app.get('/api/articles/:id/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ articleId: req.params.id })
            .sort({ createdAt: -1 })
            .limit(50);
        
        res.json(comments);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load comments' });
    }
});

// Contact form
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;
        
        // Basic spam check
        if (message.includes('http://') || message.includes('https://') || 
            message.includes('.com') || message.includes('buy now')) {
            return res.status(400).json({ error: 'Message contains suspicious content' });
        }
        
        // Save to database
        const contactMessage = new ContactMessage({
            name: sanitizeHtml(name),
            email: sanitizeHtml(email),
            subject: sanitizeHtml(subject),
            message: sanitizeHtml(message)
        });
        
        await contactMessage.save();
        
        // Send email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.SUPPORT_EMAIL,
            subject: `Contact Form: ${subject}`,
            html: `
                <h2>New Contact Message</h2>
                <p><strong>Name:</strong> ${name}</p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Subject:</strong> ${subject}</p>
                <p><strong>Message:</strong></p>
                <p>${message}</p>
                <hr>
                <p>Received at: ${new Date().toISOString()}</p>
            `
        };
        
        await transporter.sendMail(mailOptions);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Contact error:', error);
        res.status(500).json({ error: 'Message sending failed' });
    }
});

// Get article statistics
app.get('/api/stats', async (req, res) => {
    try {
        const [totalArticles, totalViews, latestArticle] = await Promise.all([
            Article.countDocuments(),
            Article.aggregate([{ $group: { _id: null, total: { $sum: "$views" } } }]),
            Article.findOne().sort({ createdAt: -1 }).select('createdAt')
        ]);
        
        res.json({
            totalArticles,
            totalViews: totalViews[0]?.total || 0,
            platformSince: latestArticle?.createdAt || new Date()
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// Generate and serve sitemap (dynamic, always fresh)
app.get('/sitemap.xml', async (req, res) => {
    try {
        const xml = await generateSitemap(getBaseUrl(req));
        res.type('application/xml; charset=utf-8');
        res.send(xml || '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>');
    } catch {
        res.type('application/xml; charset=utf-8');
        res.send('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>');
    }
});

// Generate and serve robots.txt (dynamic, always correct BASE_URL)
app.get('/robots.txt', (req, res) => {
    const txt = generateRobotsTxt(getBaseUrl(req));
    res.type('text/plain; charset=utf-8');
    res.send(txt);
});

// Initialize journal settings; sitemap/robots are generated on-demand
ensureJournalSettings().catch(() => {});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin.html`);
});