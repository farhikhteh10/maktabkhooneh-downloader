// downloader.js (Final Corrected & Complete Version)
const fs = require('fs');
const path = require('path');
const { Transform, Readable } = require('stream');
const { pipeline } = require('stream/promises');
const { setTimeout: sleep } = require('timers/promises');
const https = require('https');
const fetch = require('node-fetch'); // FIX: Use node-fetch v2 for pkg compatibility

// ===============
// Console styling (ANSI colors) and emojis
// ===============
const COLOR = {
    reset: '\u001b[0m', bold: '\u001b[1m', dim: '\u001b[2m',
    red: '\u001b[31m', green: '\u001b[32m', yellow: '\u001b[33m', blue: '\u001b[34m', magenta: '\u001b[35m', cyan: '\u001b[36m',
    lightBlue: '\u001b[94m'
};
const paint = (code, s) => `${code}${s}${COLOR.reset}`;
const paintBold = s => paint(COLOR.bold, s);
const paintGreen = s => paint(COLOR.green, s);
const paintRed = s => paint(COLOR.red, s);
const paintYellow = s => paint(COLOR.yellow, s);
const paintCyan = s => paint(COLOR.cyan, s);
const paintBoldCyan = s => `${COLOR.bold}${COLOR.cyan}${s}${COLOR.reset}`;
const paintBlue = s => paint(COLOR.blue, s);
const paintLightBlue = s => paint(COLOR.lightBlue, s);

if (process.platform === 'win32') {
    console.log(paint(COLOR.dim, '(راهنمایی: اگر کاراکترها یا ایموجی‌ها در ویندوز به درستی نمایش داده نمی‌شوند، از Windows Terminal استفاده کنید یا دستور "chcp 65001" را اجرا نمایید.)'));
}
 
const logInfo = (...a) => console.log('ℹ️', ...a);
const logStep = (...a) => console.log('▶️', ...a);
const logSuccess = (...a) => console.log('✅', ...a);
const logWarn = (...a) => console.warn('⚠️', ...a);
const logError = (...a) => console.error('❌', ...a);

// ===============
// Configuration
// ===============
const COOKIE = (() => {
    if (process.env.MK_COOKIE && process.env.MK_COOKIE.trim()) return process.env.MK_COOKIE.trim();
    if (process.env.MK_COOKIE_FILE) {
        try { return fs.readFileSync(process.env.MK_COOKIE_FILE, 'utf8').trim(); } catch { }
    }
    return 'PUT_YOUR_COOKIE_HERE';
})();
let ACTIVE_COOKIE = null;
const DEFAULT_SAMPLE_BYTES = 0;
const ORIGIN = 'https://maktabkhooneh.org';

function commonHeaders(referer) {
    const headers = {
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9,fa;q=0.8',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'x-requested-with': 'XMLHttpRequest',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36',
    };
    const ck = ACTIVE_COOKIE || COOKIE;
    if (ck && ck !== 'PUT_YOUR_COOKIE_HERE') headers['cookie'] = ck;
    if (referer) headers['referer'] = referer;
    return headers;
}

function formatBytes(bytes) {
    if (bytes == null || isNaN(bytes)) return '-';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0; let n = Number(bytes);
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2)} ${units[i]}`;
}

function formatSpeed(bytesPerSec) {
    if (!bytesPerSec || !isFinite(bytesPerSec)) return '-';
    return `${formatBytes(bytesPerSec)}/s`;
}

function buildProgressBar(ratio, width = 24) {
    const r = Math.max(0, Math.min(1, ratio || 0));
    const filled = Math.round(r * width);
    const left = width - filled;
    const bar = `${'█'.repeat(filled)}${'░'.repeat(left)}`;
    return bar;
}

function ensureCookiePresent() {
    if (!(ACTIVE_COOKIE && ACTIVE_COOKIE !== 'PUT_YOUR_COOKIE_HERE') && !(COOKIE && COOKIE !== 'PUT_YOUR_COOKIE_HERE')) {
        logError('No active session. Provide credentials in user.txt or via --user / --pass.');
        process.exit(1);
    }
}

function printUsage() {
    console.log(`${paintBoldCyan('Maktabkhooneh Downloader')} - ${paintYellow('version 1.2.0')} ${paint(COLOR.dim, '© 2025')}`);
    console.log(paint(COLOR.dim, '=============================================================\n'));
    console.log(paintBold('Required Files (next to the .exe):'));
    console.log(`  ${paintYellow('link.txt')}                    Contains one course URL per line.`);
    console.log(`  ${paintYellow('user.txt')}                    Contains email on the first line and password on the second.`);
}

function parseCLI() {
    const args = process.argv.slice(2);
    let sampleBytesToDownload = DEFAULT_SAMPLE_BYTES;
    let isVerboseLoggingEnabled = false;
    let userEmail = null;
    let userPassword = null;
    let sessionFile = 'session.json';
    let forceLogin = false;
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === '--user' || a === '--email') {
            const v = args[i + 1]; if (v) { userEmail = v; i++; }
        } else if (a.startsWith('--user=')) {
            userEmail = a.split('=')[1];
        } else if (a === '--pass' || a === '--password') {
            const v = args[i + 1]; if (v) { userPassword = v; i++; }
        } else if (a.startsWith('--pass=')) {
            userPassword = a.split('=')[1];
        } else if (a === '--session-file') {
            const v = args[i + 1]; if (v) { sessionFile = v; i++; }
        } else if (a.startsWith('--session-file=')) {
            sessionFile = a.split('=')[1];
        } else if (a.startsWith('--sample-bytes=')) {
            const v = a.split('=')[1];
            sampleBytesToDownload = parseInt(v, 10) || 0;
        } else if (a === '--sample-bytes') {
            const v = args[i + 1];
            if (v) { sampleBytesToDownload = parseInt(v, 10) || 0; i++; }
        } else if (a === '--verbose' || a === '-v') {
            isVerboseLoggingEnabled = true;
        } else if (a === '--force-login') {
            forceLogin = true;
        }
    }
    if (!sampleBytesToDownload && process.env.MK_SAMPLE_BYTES) {
        sampleBytesToDownload = parseInt(process.env.MK_SAMPLE_BYTES, 10) || 0;
    }
    return { sampleBytesToDownload, isVerboseLoggingEnabled, userEmail, userPassword, sessionFile, forceLogin };
}

function createVerboseLogger(isVerbose) {
    return { verbose: (...a) => { if (isVerbose) console.log(...a); } };
}

function extractCourseSlug(courseUrl) {
    try {
        const parsed = new URL(courseUrl);
        if (parsed.origin !== ORIGIN) {
            throw new Error('Unexpected origin: ' + parsed.origin);
        }
        const parts = parsed.pathname.split('/').filter(Boolean);
        const idx = parts.indexOf('course');
        if (idx === -1 || !parts[idx + 1]) throw new Error('Cannot parse course slug');
        return parts[idx + 1];
    } catch (e) {
        throw new Error('Invalid course URL: ' + e.message);
    }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 60_000) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
        // node-fetch v2 AbortController signal support
        options.signal = controller.signal;
        const res = await fetch(url, options);
        return res;
    } finally {
        clearTimeout(t);
    }
}

function ensureTrailingSlash(u) { return u.endsWith('/') ? u : u + '/'; }

async function getRemoteSizeAndRanges(url, referer) {
    try {
        const res = await fetchWithTimeout(url, { method: 'HEAD', headers: { ...commonHeaders(referer), accept: '*/*' } }, 60_000);
        if (res.ok) {
            const len = res.headers.get('content-length');
            const size = len ? parseInt(len, 10) : undefined;
            const acceptRanges = (res.headers.get('accept-ranges') || '').toLowerCase().includes('bytes');
            return { size, acceptRanges };
        }
    } catch { }
    try {
        const res = await fetchWithTimeout(url, { method: 'GET', headers: { ...commonHeaders(referer), range: 'bytes=0-0', accept: '*/*' } }, 60_000);
        if (res.status === 206) {
            const cr = res.headers.get('content-range');
            const m = cr && cr.match(/\/(\d+)$/);
            const size = m ? parseInt(m[1], 10) : undefined;
            try { if (res.body) { res.body.resume(); } } catch { }
            return { size, acceptRanges: true };
        }
    } catch { }
    return { size: undefined, acceptRanges: false };
}

async function fetchChapters(courseSlug, referer) {
    const apiUrl = `${ORIGIN}/api/v1/courses/${courseSlug}/chapters/`;
    const res = await fetchWithTimeout(apiUrl, { method: 'GET', headers: { ...commonHeaders(referer), accept: 'application/json' } });
    if (!res.ok) throw new Error(`Failed to fetch chapters: ${res.status} ${res.statusText}`);
    return res.json();
}

async function fetchCoreData(referer) {
    const url = `${ORIGIN}/api/v1/general/core-data/?profile=1`;
    const res = await fetchWithTimeout(url, { method: 'GET', headers: { ...commonHeaders(referer || ORIGIN), accept: 'application/json' } }, 30_000);
    if (!res.ok) throw new Error(`Core-data request failed: ${res.status} ${res.statusText}`);
    return res.json();
}

function printProfileSummary(core) {
    const isAuthenticated = !!core?.auth?.details?.is_authenticated;
    const email = core?.auth?.details?.email || core?.profile?.details?.email || '-';
    const userId = core?.auth?.details?.user_id ?? '-';
    const studentId = core?.auth?.details?.student_id ?? '-';
    const hasSubscription = !!core?.auth?.conditions?.has_subscription;
    const hasCoursePurchase = !!core?.auth?.conditions?.has_course_purchase;
    const statusText = isAuthenticated ? paintGreen('Authenticated') : paintRed('NOT authenticated');
    console.log(`🔐 Auth check: ${statusText}`);
    console.log(`👤 User: ${paintCyan(email)}  | user_id: ${paintCyan(userId)}  | student_id: ${paintCyan(studentId)}`);
    console.log(`💳 Subscription: ${hasSubscription ? paintGreen('yes') : paintYellow('no')}  | Has course purchase: ${hasCoursePurchase ? paintGreen('yes') : paintYellow('no')}`);
    return isAuthenticated;
}

function buildLectureUrl(courseSlug, chapter, unit) {
    const chapterSegment = `${encodeURIComponent(chapter.slug)}-ch${chapter.id}`;
    const unitSegment = encodeURIComponent(unit.slug);
    return `${ORIGIN}/course/${courseSlug}/${chapterSegment}/${unitSegment}/`;
}

function decodeHtmlEntities(str) {
    if (!str) return str;
    return str
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;|&apos;/g, "'")
        .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(parseInt(d, 10)))
        .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function extractVideoSources(html) {
    const urls = [];
    const re = /<source\b[^>]*?src=["']([^"'>]+)["'][^>]*>/gim;
    let m;
    while ((m = re.exec(html)) !== null) {
        const raw = m[1];
        const url = decodeHtmlEntities(raw);
        if (url && url.includes('/videos/')) urls.push(url);
    }
    return Array.from(new Set(urls));
}

function pickBestSource(urls) {
    if (!urls || urls.length === 0) return null;
    const hq = urls.find(u => /\/videos\/hq\d+/.test(u) || u.includes('/videos/hq'));
    return hq || urls[0];
}

function sanitizeName(name) {
    return name.replace(/[\/:*?"<>|]/g, ' ').replace(/[\s\u200c\u200f\u202a\u202b]+/g, ' ').trim().slice(0, 150);
}

function extractAttachmentLinks(html) {
    const results = new Set();
    if (!html) return [];
    const blockRe = /<div[^>]*class=["'][^"'>]*unit-content--download[^"'>]*["'][^>]*>[\s\S]*?<\/div>/gim;
    let m;
    while ((m = blockRe.exec(html)) !== null) {
        const block = m[0];
        const aRe = /<a[^>]+href=["']([^"'>]+)["'][^>]*>/gim;
        let a;
        while ((a = aRe.exec(block)) !== null) {
            const raw = a[1];
            const url = decodeHtmlEntities(raw);
            if (url && /attachments/i.test(url)) {
                results.add(url);
            }
        }
    }
    return Array.from(results);
}

async function readSessionFile(file) {
    try {
        const txt = await fs.promises.readFile(file, 'utf8');
        const data = JSON.parse(txt);
        if (data && data.users) return data;
        if (data && typeof data.cookie === 'string') {
            return {
                users: { 'default': { cookie: data.cookie, updated: data.updated || new Date().toISOString() } },
                lastUsed: 'default'
            };
        }
    } catch { }
    return null;
}

async function writeSessionFileMulti(file, email, cookie, existing) {
    const key = (email || 'default').trim().toLowerCase();
    let data = existing && existing.users ? existing : { users: {}, lastUsed: key };
    data.users[key] = { cookie, updated: new Date().toISOString() };
    data.lastUsed = key;
    try { await fs.promises.writeFile(file, JSON.stringify(data, null, 2), 'utf8'); } catch { }
}

class SimpleCookieStore {
    constructor() { this.map = new Map(); }
    setCookieLine(line) {
        if (!line) return;
        const seg = line.split(';')[0];
        const eq = seg.indexOf('=');
        if (eq === -1) return;
        const k = seg.slice(0, eq).trim();
        const v = seg.slice(eq + 1).trim();
        if (k) this.map.set(k, v);
    }
    applySetCookie(arr) { (arr || []).forEach(l => this.setCookieLine(l)); }
    get(name) { return this.map.get(name); }
    headerString() { return Array.from(this.map.entries()).map(([k, v]) => `${k}=${v}`).join('; '); }
}

function rawRequest(urlStr, { method = 'GET', headers = {}, body = null } = {}) {
    const u = new URL(urlStr);
    return new Promise((resolve, reject) => {
        const opts = { method, hostname: u.hostname, path: u.pathname + (u.search || ''), protocol: u.protocol, headers };
        const req = https.request(opts, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                resolve({
                    status: res.statusCode || 0,
                    headers: res.headers,
                    body: Buffer.concat(chunks).toString('utf8')
                });
            });
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

async function loginWithCredentialsInline(email, password, verbose = () => { }) {
    if (!email || !password) throw new Error('Email & password required for login');
    const store = new SimpleCookieStore();
    const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36';
    const dbg = (...a) => verbose('[login]', ...a);
    let r = await rawRequest(`${ORIGIN}/accounts/login/`, {
        method: 'GET', headers: { 'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' }
    });
    store.applySetCookie(r.headers['set-cookie']);
    let csrf = store.get('csrftoken') || null;
    if (!csrf) {
        const r2 = await rawRequest(`${ORIGIN}/api/v1/general/core-data/?profile=1`, {
            method: 'GET', headers: { 'User-Agent': UA, 'Accept': 'application/json' }
        });
        store.applySetCookie(r2.headers['set-cookie']);
        try { const j2 = JSON.parse(r2.body); csrf = csrf || j2?.auth?.csrf || null; } catch { }
        if (!csrf) csrf = store.get('csrftoken') || null;
    }
    if (!csrf) throw new Error('Cannot obtain CSRF token');

    const cookieHeader = () => store.headerString();
    const baseHeaders = () => ({ 'User-Agent': UA, 'Accept': 'application/json, text/javascript, */*; q=0.01', 'X-Requested-With': 'XMLHttpRequest' });
    const addCsrfHeaders = (h = {}) => ({ ...h, 'X-CSRFToken': csrf, 'Origin': ORIGIN, 'Referer': `${ORIGIN}/accounts/login/` });

    const formCheck = new URLSearchParams();
    formCheck.append('csrfmiddlewaretoken', csrf);
    formCheck.append('tessera', email);
    formCheck.append('g-recaptcha-response', '');
    r = await rawRequest(`${ORIGIN}/api/v1/auth/check-active-user`, {
        method: 'POST',
        headers: addCsrfHeaders({ ...baseHeaders(), 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Cookie': cookieHeader() }),
        body: formCheck.toString()
    });
    store.applySetCookie(r.headers['set-cookie']);
    let jCheck = null; try { jCheck = JSON.parse(r.body); } catch { }
    if (!jCheck || jCheck.status !== 'success' || jCheck.message !== 'get-pass') {
        throw new Error('Login flow step 1 failed: ' + (jCheck?.message || 'Unknown error'));
    }

    const formLogin = new URLSearchParams();
    formLogin.append('csrfmiddlewaretoken', csrf);
    formLogin.append('tessera', email);
    formLogin.append('hidden_username', email);
    formLogin.append('password', password);
    formLogin.append('g-recaptcha-response', '');
    r = await rawRequest(`${ORIGIN}/api/v1/auth/login-authentication`, {
        method: 'POST',
        headers: addCsrfHeaders({ ...baseHeaders(), 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Cookie': cookieHeader() }),
        body: formLogin.toString()
    });
    store.applySetCookie(r.headers['set-cookie']);
    let jLogin = null; try { jLogin = JSON.parse(r.body); } catch { }
    if (!jLogin || jLogin.status !== 'success') throw new Error('Login failed: ' + (jLogin?.message || 'Invalid credentials'));

    const sessionid = store.get('sessionid');
    const csrftoken = store.get('csrftoken') || csrf;
    if (!sessionid) throw new Error('Session cookie missing after login');
    ACTIVE_COOKIE = `csrftoken=${csrftoken}; sessionid=${sessionid}`;
    return true;
}

async function prepareSession({ userEmail, userPassword, sessionFile, verbose, forceLogin }) {
    const verify = async () => {
        try {
            if (!ACTIVE_COOKIE) return null;
            verbose('Verifying existing session cookie...');
            const core = await fetchCoreData(ORIGIN);
            const ok = !!core?.auth?.details?.is_authenticated;
            if (ok) {
                logInfo('Session valid' + (userEmail ? ` (user: ${userEmail})` : ''));
                return core;
            }
            logWarn('Stored session not authenticated');
            return null;
        } catch (e) {
            verbose('Verify failed: ' + e.message);
            return null;
        }
    };
    if (COOKIE && COOKIE !== 'PUT_YOUR_COOKIE_HERE') {
        ACTIVE_COOKIE = COOKIE;
        verbose('Using cookie from env / file override');
        const core = await verify();
        if (core) return { core, source: 'env' };
    }
    let sessionData = null;
    if (sessionFile) {
        sessionData = await readSessionFile(sessionFile);
    }
    const desiredUserKey = userEmail ? userEmail.trim().toLowerCase() : null;
    if (sessionData && desiredUserKey && !forceLogin) {
        const entry = sessionData.users[desiredUserKey];
        if (entry && entry.cookie) {
            ACTIVE_COOKIE = entry.cookie;
            logStep(`Loaded stored session for user ${desiredUserKey}`);
            const core = await verify();
            if (core) {
                if (userPassword) verbose('Reusing valid stored session; skipping login because --force-login not set');
                return { core, source: 'stored-user' };
            }
            logWarn('Stored session invalid; will attempt fresh login if password provided.');
            ACTIVE_COOKIE = null;
        }
    }
    if (desiredUserKey && userPassword && (!ACTIVE_COOKIE || forceLogin)) {
        try {
            logStep('Attempting login for ' + desiredUserKey);
            await loginWithCredentialsInline(userEmail, userPassword, verbose);
            if (ACTIVE_COOKIE && sessionFile) {
                await writeSessionFileMulti(sessionFile, userEmail, ACTIVE_COOKIE, sessionData);
                logSuccess('Login success; session stored for user ' + desiredUserKey);
            }
            const core = await verify();
            if (core) return { core, source: 'fresh-login' };
        } catch (e) {
            logError('Login failed: ' + e.message);
            process.exit(1);
        }
    }
    if (!ACTIVE_COOKIE) {
        logWarn('No usable session found. Provide credentials in user.txt or use --user and --pass to create one.');
    }
    return { core: null, source: 'none' };
}

function extractSubtitleLinks(html) {
    const results = new Set();
    if (!html) return [];
    const re = /<track\b[^>]*?src=["']([^"'>]+)["'][^>]*>/gim;
    let m;
    while ((m = re.exec(html)) !== null) {
        const raw = m[1];
        const url = decodeHtmlEntities(raw);
        if (url) results.add(url);
    }
    return Array.from(results);
}

class ByteLimit extends Transform {
    constructor(limit, onLimit) { super(); this.limit = limit; this.seen = 0; this._hit = false; this._onLimit = onLimit; }
    _transform(chunk, enc, cb) {
        if (this.limit <= 0) { this.push(chunk); return cb(); }
        const remaining = this.limit - this.seen;
        if (remaining <= 0) { return cb(); }
        const buf = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        this.push(buf);
        this.seen += buf.length;
        if (!this._hit && this.seen >= this.limit) {
            this.end();
            this._hit = true;
            if (typeof this._onLimit === 'function') { try { this._onLimit(); } catch { } }
        }
        cb();
    }
}

async function downloadToFile(url, filePath, referer, maxRetries = 3, sampleBytes = 0, label = '') {
    let existingFinalSize = 0;
    try { const stat = fs.statSync(filePath); existingFinalSize = stat.size; if (existingFinalSize > 0 && sampleBytes > 0) return 'exists'; } catch { }
    const tmpPath = filePath + '.part';
    let existingTmpSize = 0;
    try { const stat = fs.statSync(tmpPath); existingTmpSize = stat.size; } catch { }

    let remoteInfo;
    if (sampleBytes === 0 && existingFinalSize > 0) {
        remoteInfo = await getRemoteSizeAndRanges(url, referer);
        if (remoteInfo.size && existingFinalSize >= remoteInfo.size) {
            return 'exists';
        }
    }

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            let resumeOffset = 0;
            if (sampleBytes <= 0) {
                if (existingTmpSize > 0) resumeOffset = existingTmpSize;
                else if (existingFinalSize > 0) {
                    if (!remoteInfo) remoteInfo = await getRemoteSizeAndRanges(url, referer);
                    if (remoteInfo.acceptRanges) {
                        try { await fs.promises.rename(filePath, tmpPath); resumeOffset = existingFinalSize; } catch { }
                    }
                }
            }
            
            const requestInit = { method: 'GET', headers: { ...commonHeaders(referer), accept: 'video/mp4,application/octet-stream,*/*' } };
            if (sampleBytes > 0) {
                requestInit.headers['range'] = `bytes=0-${Math.max(0, sampleBytes - 1)}`;
            } else if (resumeOffset > 0) {
                requestInit.headers['range'] = `bytes=${resumeOffset}-`;
            }

            const res = await fetchWithTimeout(url, requestInit, 600_000); // 10 minutes timeout
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            if (resumeOffset > 0 && res.status !== 206) {
                try { await fs.promises.unlink(tmpPath); } catch { }
                resumeOffset = 0;
                throw new Error('Server did not honor range; restarting from 0');
            }

            await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
            const write = fs.createWriteStream(tmpPath, { flags: resumeOffset > 0 ? 'a' : 'w' });
            
            // FIX: The body from node-fetch@2 is already a Node.js stream.
            const readable = res.body;

            const contentLengthHeader = res.headers.get('content-length');
            const fullLength = contentLengthHeader ? parseInt(contentLengthHeader, 10) : undefined;
            let expectedTotal;
            const contentRange = res.headers.get('content-range');
            const crMatch = contentRange && contentRange.match(/\/(\d+)$/);
            if (sampleBytes > 0) expectedTotal = sampleBytes;
            else if (crMatch) expectedTotal = parseInt(crMatch[1], 10);
            else if (fullLength && resumeOffset > 0) expectedTotal = resumeOffset + fullLength;
            else expectedTotal = fullLength;
            let downloadedBytes = resumeOffset;
            const startedAt = Date.now();

            const render = (final = false) => {
                const elapsedSec = Math.max(0.001, (Date.now() - startedAt) / 1000);
                const speed = (downloadedBytes - resumeOffset) / elapsedSec;
                let ratio = expectedTotal ? (downloadedBytes / expectedTotal) : 0;
                if (final) ratio = 1;
                const bar = buildProgressBar(ratio);
                const pct = `${(Math.min(1, ratio) * 100).toFixed(1)}%`;
                const sizeStr = `${formatBytes(downloadedBytes)}${expectedTotal ? ' / ' + formatBytes(expectedTotal) : ''}`;
                const line = `  ⬇️  [${bar}] ${pct}  ${sizeStr}  ${formatSpeed(speed)}`;
                process.stdout.write(`\r${line}`);
            };

            const counter = new Transform({
                transform(chunk, _enc, cb) {
                    downloadedBytes += chunk.length;
                    if (downloadedBytes === resumeOffset + chunk.length || downloadedBytes % 65536 < 8192) render();
                    cb(null, chunk);
                }
            });

            await pipeline(readable, counter, write);

            render(true);
            process.stdout.write('\n');
            await fs.promises.rename(tmpPath, filePath);
            return 'downloaded';
        } catch (err) {
            process.stdout.write('\n');
            if (attempt < maxRetries) {
                logWarn(`Retry ${attempt}/${maxRetries} for ${path.basename(filePath)} after error: ${err.message}`);
                await sleep(2000 * attempt);
                continue;
            }
            throw err;
        }
    }
}

async function main() {
    try {
        const cliArgs = parseCLI();
        const { sampleBytesToDownload, isVerboseLoggingEnabled, sessionFile, forceLogin } = cliArgs;
        const { verbose } = createVerboseLogger(isVerboseLoggingEnabled);

        // FIX: Use path relative to the executable for robust file access
        const baseDir = process.pkg ? path.dirname(process.execPath) : __dirname;

        let userEmailFromFile = null, userPasswordFromFile = null;
        try {
            const userContent = fs.readFileSync(path.join(baseDir, 'user.txt'), 'utf8').trim().split(/\r?\n/);
            if (userContent.length >= 2 && userContent[0].trim() && userContent[1].trim()) {
                userEmailFromFile = userContent[0].trim();
                userPasswordFromFile = userContent[1].trim();
                logInfo('Credentials loaded from user.txt');
            } else {
                logWarn('user.txt is incomplete.');
            }
        } catch (e) {
            logError("Could not read 'user.txt'. Make sure it's next to the executable.");
            printUsage();
            await sleep(5000);
            process.exit(1);
        }

        const userEmail = cliArgs.userEmail || userEmailFromFile;
        const userPassword = cliArgs.userPassword || userPasswordFromFile;

        let courseUrls = [];
        try {
            const linkContent = fs.readFileSync(path.join(baseDir, 'link.txt'), 'utf8');
            courseUrls = linkContent.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
            if (courseUrls.length === 0) throw new Error('link.txt is empty.');
            logInfo(`${courseUrls.length} course link(s) loaded from link.txt`);
        } catch (e) {
            logError("Could not read 'link.txt'. Make sure it's next to the executable and not empty.");
            printUsage();
            await sleep(5000);
            process.exit(1);
        }
        
        const prep = await prepareSession({ userEmail, userPassword, sessionFile, verbose, forceLogin });
        ensureCookiePresent();

        let coreData = prep.core;
        if (!coreData) {
            coreData = await fetchCoreData(ORIGIN);
        }
        const ok = printProfileSummary(coreData);
        if (!ok) {
            logError('Authentication failed. Please check your credentials in user.txt.');
            await sleep(5000);
            process.exit(1);
        }

        for (const courseUrl of courseUrls) {
            console.log('\n' + '═'.repeat(60));
            logStep(`Processing course: ${paintBold(courseUrl)}`);
            try {
                const normalizedCourseUrl = ensureTrailingSlash(courseUrl.trim());
                const courseSlug = extractCourseSlug(normalizedCourseUrl);
                const courseDisplayName = sanitizeName(decodeURIComponent(courseSlug));
                
                // FIX: Save downloads relative to the executable's location
                const outputRootFolder = path.resolve(baseDir, 'download', courseDisplayName);
                
                try { await fs.promises.mkdir(outputRootFolder, { recursive: true }); } catch { }

                console.log(`📚 Course slug: ${paintBold(decodeURIComponent(courseSlug))}`);
                console.log(`📁 Output folder: ${paintCyan(outputRootFolder)}`);
                if (sampleBytesToDownload > 0) {
                    console.log(`🎯 Sample mode: downloading first ${paintBold(String(sampleBytesToDownload))} bytes`);
                }

                const chaptersData = await fetchChapters(courseSlug, normalizedCourseUrl);
                const chapters = Array.isArray(chaptersData?.chapters) ? chaptersData.chapters : [];
                if (chapters.length === 0) {
                    logError('No chapters found. Check the URL and your access rights.');
                    continue;
                }
                
                let totalUnits = 0, downloadedCount = 0, skippedCount = 0, failedCount = 0;
                for (let chapterIndex = 0; chapterIndex < chapters.length; chapterIndex++) {
                    const chapter = chapters[chapterIndex];
                    const chapterOrder = String(chapterIndex + 1).padStart(2, '0');
                    const chapterFolder = path.join(outputRootFolder, `${chapterOrder} - ${sanitizeName(chapter.title || 'chapter')}`);
                    console.log(`📖 Chapter ${chapterIndex + 1}/${chapters.length}: ${paintBold(chapter.title || chapter.slug)}`);

                    const units = Array.isArray(chapter.unit_set) ? chapter.unit_set : [];
                    for (let unitIndex = 0; unitIndex < units.length; unitIndex++) {
                        const unit = units[unitIndex];
                        if (!unit?.status || unit?.type !== 'lecture') continue;
                        totalUnits++;
                        const unitOrder = String(unitIndex + 1).padStart(2, '0');
                        const baseFileName = `${unitOrder} - ${sanitizeName(unit.title || 'lecture')}.mp4`;
                        const finalFileName = sampleBytesToDownload > 0 ? baseFileName.replace(/\.mp4$/i, '.sample.mp4') : baseFileName;
                        const outputFilePath = path.join(chapterFolder, finalFileName);

                        if (unit.locked) {
                            logWarn(`🔒 Locked/No access: ${finalFileName}`);
                            skippedCount++;
                            continue;
                        }

                        const lectureUrl = buildLectureUrl(courseSlug, chapter, unit);
                        try {
                            const res = await fetchWithTimeout(lectureUrl, { headers: { ...commonHeaders(normalizedCourseUrl), accept: 'text/html' } });
                            if (!res.ok) throw new Error(`HTTP ${res.status}`);
                            const html = await res.text();
                            const videoSources = extractVideoSources(html);
                            const bestSourceUrl = pickBestSource(videoSources);
                            if (!bestSourceUrl) { logWarn(`No video source found for: ${finalFileName}`); skippedCount++; continue; }

                            console.log(`📥 Downloading: ${finalFileName}`);
                            const status = await downloadToFile(bestSourceUrl, outputFilePath, lectureUrl, 3, sampleBytesToDownload, '');
                            if (status === 'exists') { console.log(paintYellow(`🟡 SKIP exists: ${finalFileName}`)); skippedCount++; }
                            else { logSuccess(`DOWNLOADED: ${finalFileName}`); downloadedCount++; }
                            
                            // Attachments & Subtitles can be added here if needed
                            
                            await sleep(400);
                        } catch (err) {
                            logError(`FAIL ${finalFileName}: ${err.message}`);
                            failedCount++;
                        }
                    }
                }
                console.log('—'.repeat(40));
                console.log(`📊 Summary for ${courseDisplayName}:`);
                console.log(`  ✅ Downloaded: ${paintGreen(String(downloadedCount))}`);
                console.log(`  🟡 Skipped: ${paintYellow(String(skippedCount))}`);
                console.log(`  ❌ Failed: ${paintRed(String(failedCount))}`);

            } catch (courseError) {
                logError(`FATAL ERROR processing course ${courseUrl}: ${courseError.message}`);
            }
        }
        
        console.log('\n' + '═'.repeat(60));
        logSuccess('All courses from link.txt have been processed.');
        await sleep(5000);

    } catch (err) {
        logError('A fatal error occurred:', err.message);
        await sleep(10000); // Wait 10 seconds before exit on error
        process.exit(1);
    }
}

main();