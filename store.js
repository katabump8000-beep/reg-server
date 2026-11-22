"use strict";
/**
 * store.js — تخزين بسيط بملف JSON (بدون أي حزمة خارجية) لمنصة التسجيل المركزية.
 * كل كتابة تتم بأسلوب آمن: كتابة إلى ملف مؤقت ثم rename (atomic) لمنع تلف الملف
 * عند انقطاع الكهرباء/التشغيل أثناء الحفظ.
 *
 * البنية:
 * {
 *   bots:        { [botId]: { apiKeyHash, createdAt } },
 *   sessions:    { [sessionId]: {sessionId, flowToken, botId, groupJid, senderJid, code,
 *                                status, used, createdAt, expiresAt} },
 *   codeIndex:   { "<botId>|<groupJid>|<code>": sessionId },
 *   registrations: { "<botId>|<groupJid>|<senderNumber>": {nickname, referrer, gender, age,
 *                                senderJid, registeredAt, used, joinApprovedAt, welcomedAt} },
 *   nonces:      { [nonce]: expiresAt }   // لمنع Replay Attacks
 * }
 */

const fs = require("fs");
const path = require("path");

const DATA_DIR = String(process.env.DATA_DIR || path.join(__dirname, "data")).trim();
const DB_FILE = path.join(DATA_DIR, "database.json");

function emptyDb() {
    return { bots: {}, sessions: {}, codeIndex: {}, registrations: {}, nonces: {} };
}

function load() {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        if (!fs.existsSync(DB_FILE)) return emptyDb();
        const raw = fs.readFileSync(DB_FILE, "utf8");
        const parsed = JSON.parse(raw || "{}");
        return Object.assign(emptyDb(), parsed);
    } catch (e) {
        console.error("[store] فشل تحميل قاعدة البيانات، سيُستخدم تخزين فارغ:", e?.message || e);
        return emptyDb();
    }
}

let db = load();
let saveTimer = null;

/* البوتات (API keys) تُقرأ من متغير بيئة BOT_KEYS بدل ملف القرص المؤقت، حتى لا تضيع عند نوم
   الخدمة المجاني وإعادة إقلاعها (القرص هناك غير دائم). الصيغة:
   BOT_KEYS = bot1:secret1,bot2:secret2,bot3:secret3
   create-bot.js يبقى مفيداً فقط لتوليد سر عشوائي آمن تضيفه بنفسك لهالمتغير. */
(function applyBotKeysEnv() {
    const raw = String(process.env.BOT_KEYS || "").trim();
    if (!raw) return;
    for (const pair of raw.split(",")) {
        const idx = pair.indexOf(":");
        if (idx < 1) continue;
        const id = pair.slice(0, idx).trim();
        const secret = pair.slice(idx + 1).trim();
        if (id && secret) db.bots[id] = { apiKeySecret: secret, createdAt: (db.bots[id] && db.bots[id].createdAt) || Date.now() };
    }
})();

function saveNow() {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        const tmp = DB_FILE + ".tmp-" + process.pid;
        fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
        fs.renameSync(tmp, DB_FILE);
    } catch (e) {
        console.error("[store] فشل حفظ قاعدة البيانات:", e?.message || e);
    }
}

/** حفظ مُجمَّع (debounced) لتقليل الكتابة على القرص تحت ضغط عالٍ */
function save() {
    if (saveTimer) return;
    saveTimer = setTimeout(() => { saveTimer = null; saveNow(); }, 200);
}

function flushSync() {
    if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
    saveNow();
}

process.on("SIGINT", () => { flushSync(); process.exit(0); });
process.on("SIGTERM", () => { flushSync(); process.exit(0); });

// -------------------- تنظيف دوري --------------------
function sweep() {
    const now = Date.now();
    for (const [id, s] of Object.entries(db.sessions)) {
        if (now > s.expiresAt + 10 * 60 * 1000) {
            delete db.codeIndex[`${s.botId}|${s.groupJid}|${s.code}`];
            delete db.sessions[id];
        }
    }
    for (const [n, exp] of Object.entries(db.nonces)) {
        if (now > exp) delete db.nonces[n];
    }
    save();
}
setInterval(sweep, 60 * 1000).unref?.();

module.exports = { db, save, flushSync, DATA_DIR };
