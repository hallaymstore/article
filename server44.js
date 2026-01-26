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
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://abumafia0:abumafia0@abumafia.h1trttg.mongodb.net/article1?appName=abumafia');

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
        journalTitle: 'HALLAYM SCI-Journal',
        issnOnline: 'Pending',
        publisher: 'Hallaym',
        scope: 'Multidisciplinary',
        country: 'Uzbekistan',
        contactEmail: 'admin@hallaym.site',
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
        const articles = await Article.find({ issueId: issue._id }).sort({ publicationDate: -1 }).select('title slug author publicationDate abstract coverImage volume issue year doi license keywords authors pages section');
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
    try {
        const { slug } = req.params;
        const original = String(req.query.original || '').trim() === '1';

        const article = await Article.findOne({ slug });
        if (!article) return res.status(404).json({ error: 'Article not found' });

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

        // --- Build HTML (cover page + article pages)
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
                return dt.toISOString().slice(0,10);
            } catch { return ''; }
        };

        const journalTitle = settings?.journalTitle || 'The Global Science';
        const scope = settings?.scope || 'Multidisciplinary Open Access';
        const publisher = settings?.publisher || '';
        const issnOnline = settings?.issnOnline || 'Pending';
        const issnPrint = settings?.issnPrint || '';

        const volumeIssue = (article.volume && article.issue) ? `Volume ${article.volume}, Issue ${article.issue}` : (article.volume ? `Volume ${article.volume}` : '');
        const year = article.year || (article.publicationDate ? new Date(article.publicationDate).getFullYear() : '');
        const pubDate = fmtDate(article.publishedAt || article.publicationDate || article.createdAt);
        const doi = article.doi ? `https://doi.org/${article.doi}` : '';

        const authors = (Array.isArray(article.authors) && article.authors.length)
            ? article.authors.map(a => a?.name).filter(Boolean).join(', ')
            : (article.author || '');

        const affiliations = (Array.isArray(article.authors) && article.authors.length)
            ? article.authors.map(a => a?.affiliation).filter(Boolean)
            : [];

        const bodyParts = [];
        if (article.abstract) bodyParts.push(`<section class="box avoid"><h2>Abstract</h2><p>${esc(article.abstract)}</p></section>`);
        if (article.introduction) bodyParts.push(`<section class="avoid"><h2>Introduction</h2><p>${esc(article.introduction)}</p></section>`);
        if (Array.isArray(article.body)) {
            article.body.forEach(sec => {
                if (sec?.heading) bodyParts.push(`<section class="avoid"><h2>${esc(sec.heading)}</h2>${sec?.content ? `<p>${esc(sec.content)}</p>` : ''}</section>`);
                else if (sec?.content) bodyParts.push(`<section class="avoid"><p>${esc(sec.content)}</p></section>`);
            });
        }
        if (article.conclusion) bodyParts.push(`<section class="avoid"><h2>Conclusion</h2><p>${esc(article.conclusion)}</p></section>`);

        const refs = Array.isArray(article.references) ? article.references : [];
        const refsHtml = refs.length
            ? `<ol class="refs">${refs.map(r => `<li>${esc(r)}</li>`).join('')}</ol>`
            : `<div class="muted">—</div>`;

        const coverImg = article.coverImage ? `<img class="coverImg" src="${esc(article.coverImage)}" alt="cover" />` : '';

        const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${esc(article.title)} | ${esc(journalTitle)}</title>
  <style>
    @page { size: A4; margin: 18mm 16mm 18mm 16mm; }
    body { font-family: Arial, Helvetica, sans-serif; color: #0f172a; }
    .cover {
      position: relative;
      height: 100%;
      min-height: 252mm;
      border-radius: 14px;
      overflow: hidden;
      border: 1px solid rgba(15,23,42,.12);
    }
    .coverTop {
      padding: 22mm 18mm 0 18mm;
      display:flex;
      gap:14mm;
      align-items:flex-start;
    }
    .logoBox {
      width: 46mm;
      height: 46mm;
      border-radius: 16px;
      background: linear-gradient(135deg, #4f46e5, #d946ef);
      box-shadow: 0 18px 45px rgba(0,0,0,.18);
      flex: 0 0 auto;
    }
    .coverTitle { font-size: 28px; font-weight: 800; margin: 0; letter-spacing: -0.2px; }
    .coverSub { margin-top: 6px; font-size: 12px; color: rgba(15,23,42,.72); }
    .coverMeta {
      margin-top: 14mm;
      display:grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      padding: 0 18mm 0 18mm;
    }
    .metaCard{
      border: 1px solid rgba(15,23,42,.12);
      border-radius: 12px;
      padding: 10px 12px;
      background: rgba(248,250,252,.9);
    }
    .label{ font-size: 10px; text-transform: uppercase; letter-spacing: .12em; color: rgba(15,23,42,.6); }
    .value{ margin-top: 4px; font-size: 12px; font-weight: 700; }
    .coverImg {
      position:absolute;
      left:0; right:0; bottom:0;
      width:100%;
      height: 92mm;
      object-fit: cover;
      filter: saturate(1.05);
    }
    .coverFade{
      position:absolute;
      left:0; right:0; bottom:0;
      height: 92mm;
      background: linear-gradient(to top, rgba(2,6,23,.08), rgba(2,6,23,0));
      pointer-events:none;
    }

    /* Article pages */
    h1 { font-size: 22px; margin: 0 0 6px 0; letter-spacing:-0.2px; }
    h2 { font-size: 14px; margin: 14px 0 6px 0; }
    p  { font-size: 11.5px; line-height: 1.7; margin: 0 0 8px 0; }
    .muted { color: rgba(15,23,42,.65); font-size: 11px; }
    .pageBreak { page-break-before: always; break-before: page; }
    .box {
      border: 1px solid rgba(15,23,42,.12);
      border-radius: 12px;
      padding: 10px 12px;
      background: rgba(248,250,252,.9);
    }
    .avoid { break-inside: avoid; page-break-inside: avoid; }
    .topMeta { margin-top: 8px; display:flex; flex-wrap:wrap; gap:10px; }
    .chip { border: 1px solid rgba(15,23,42,.12); border-radius: 999px; padding: 6px 10px; font-size: 10.5px; background: rgba(248,250,252,.9); }
    .refs { font-size: 11px; line-height: 1.55; padding-left: 16px; }
    .refs li { margin: 0 0 6px 0; }
    .aff { margin-top: 4px; font-size: 11px; color: rgba(15,23,42,.72); }
  </style>
</head>
<body>

  <!-- COVER PAGE -->
  <section class="cover">
    <div class="coverTop">
      <div class="logoBox" aria-hidden="true"></div>
      <div>
        <div class="label">${esc(scope)}</div>
        <h1 class="coverTitle">${esc(journalTitle)}</h1>
        <div class="coverSub">
          Website: <strong>${esc(baseUrl.replace(/^https?:\/\//,'').replace(/\/$/,'') )}</strong>
          ${publisher ? ` • Publisher: <strong>${esc(publisher)}</strong>` : ''}
        </div>
        <div class="coverSub" style="margin-top:6px;">
          ISSN (Online): <strong>${esc(issnOnline)}</strong>
          ${issnPrint ? ` • ISSN (Print): <strong>${esc(issnPrint)}</strong>` : ''}
        </div>
      </div>
    </div>

    <div class="coverMeta">
      <div class="metaCard">
        <div class="label">Article title</div>
        <div class="value">${esc(article.title)}</div>
      </div>
      <div class="metaCard">
        <div class="label">Authors</div>
        <div class="value">${esc(authors || '—')}</div>
      </div>
      <div class="metaCard">
        <div class="label">Issue</div>
        <div class="value">${esc([volumeIssue, year].filter(Boolean).join(' • ') || '—')}</div>
      </div>
      <div class="metaCard">
        <div class="label">Published</div>
        <div class="value">${esc(pubDate || '—')}</div>
      </div>
      <div class="metaCard">
        <div class="label">DOI</div>
        <div class="value">${esc(doi || '—')}</div>
      </div>
      <div class="metaCard">
        <div class="label">License</div>
        <div class="value">${esc(article.license || settings?.defaultLicense || 'CC BY 4.0')}</div>
      </div>
    </div>

    ${coverImg}
    <div class="coverFade"></div>
  </section>

  <!-- ARTICLE PAGES -->
  <div class="pageBreak"></div>

  <header>
    <h1>${esc(article.title)}</h1>
    <div class="muted">${esc(authors || '')}</div>
    ${affiliations.length ? `<div class="aff">${esc(affiliations.join(' • '))}</div>` : ''}
    <div class="topMeta">
      <div class="chip">ISSN (Online): ${esc(issnOnline)}</div>
      ${volumeIssue ? `<div class="chip">${esc(volumeIssue)}${year ? ` • ${esc(String(year))}` : ''}</div>` : ''}
      ${article.pages ? `<div class="chip">Pages: ${esc(article.pages)}</div>` : ''}
      ${article.section ? `<div class="chip">${esc(article.section)}</div>` : ''}
      ${doi ? `<div class="chip">DOI: ${esc(doi)}</div>` : ''}
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
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });

        try {
            const page = await browser.newPage();
            await page.setContent(html, { waitUntil: 'networkidle0' });

            const pdfBuffer = await page.pdf({
                format: 'A4',
                printBackground: true,
                displayHeaderFooter: true,
                headerTemplate: `
                    <div style="width:100%; padding:0 16mm; font-size:9px; color:rgba(15,23,42,.65); display:flex; justify-content:space-between; align-items:center;">
                      <div style="font-weight:700;">${journalTitle}</div>
                      <div>${baseUrl.replace(/^https?:\/\//,'').replace(/\/$/,'')}</div>
                    </div>
                `,
                footerTemplate: `
                    <div style="width:100%; padding:0 16mm; font-size:9px; color:rgba(15,23,42,.65); display:flex; justify-content:space-between; align-items:center;">
                      <div>ISSN (Online): ${issnOnline}</div>
                      <div>Page <span class="pageNumber"></span> / <span class="totalPages"></span></div>
                    </div>
                `,
                margin: { top: '22mm', bottom: '18mm', left: '16mm', right: '16mm' }
            });

            res.setHeader('Content-Disposition', `attachment; filename="${(article.title || 'article').replace(/[^a-z0-9_-]+/gi, '_')}_TGS.pdf"`);
            res.setHeader('Content-Type', 'application/pdf');
            res.send(pdfBuffer);
        } finally {
            await browser.close();
        }
    } catch (e) {
        console.error('PDF generate error:', e);
        res.status(500).json({ error: 'PDF generation failed' });
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
        .select('title slug author publicationDate abstract coverImage volume issue year doi license keywords authors pages section');
        
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
                .select('title slug author publicationDate abstract coverImage volume issue year doi license keywords authors pages section'),
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