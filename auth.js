"use strict";
/**
 * auth.js — توقيع وتحقق طلبات البوتات (API Key + HMAC + منع Replay).
 *
 * كل طلب من بوت يجب أن يحمل الترويسات:
 *   X-Bot-Id:     معرّف البوت
 *   X-Timestamp:  Date.now() وقت الإرسال (ms)
 *   X-Nonce:      قيمة عشوائية فريدة لكل طلب (uuid أو hex عشوائي)
 *   X-Signature:  HMAC-SHA256(apiKeySecret, `${method}\n${path}\n${timestamp}\n${nonce}\n${rawBody}`) بصيغة hex
 *
 * هذا يمنع:
 *  - انتحال البوت (لا أحد يعرف المفتاح غيره وغير السيرفر، والمفتاح لا يُرسل بالطلب نفسه).
 *  - إعادة تشغيل نفس الطلب (nonce مستخدم مرة واحدة + صلاحية 5 دقائق للـ timestamp).
 *  - التلاعب بالجسم أثناء النقل (أي تعديل يُبطل التوقيع).
 */

const crypto = require("crypto");
const { db, save } = require("./store");

const MAX_SKEW_MS = 5 * 60 * 1000; // 5 دقائق

function timingSafeEqual(a, b) {
    const ab = Buffer.from(String(a || ""), "utf8");
    const bb = Buffer.from(String(b || ""), "utf8");
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
}

function sign(apiKeySecret, method, path, timestamp, nonce, rawBody) {
    const payload = `${method}\n${path}\n${timestamp}\n${nonce}\n${rawBody || ""}`;
    return crypto.createHmac("sha256", apiKeySecret).update(payload).digest("hex");
}

/** Rate limiting بسيط بالذاكرة: نافذة دقيقة واحدة لكل بوت */
const rateBuckets = new Map();
function rateLimited(botId, limitPerMinute) {
    const now = Date.now();
    const windowStart = now - 60 * 1000;
    let arr = rateBuckets.get(botId) || [];
    arr = arr.filter((t) => t > windowStart);
    if (arr.length >= limitPerMinute) { rateBuckets.set(botId, arr); return true; }
    arr.push(now);
    rateBuckets.set(botId, arr);
    return false;
}

/** Middleware للتحقق من توقيع وهوية البوت */
function verifyBot(opts) {
    const limitPerMinute = (opts && opts.limitPerMinute) || 60;
    return function (req, res, next) {
        const botId = String(req.header("X-Bot-Id") || "").trim();
        const timestamp = Number(req.header("X-Timestamp") || 0);
        const nonce = String(req.header("X-Nonce") || "").trim();
        const signature = String(req.header("X-Signature") || "").trim();

        if (!botId || !timestamp || !nonce || !signature) {
            return res.status(401).json({ ok: false, error: "missing_auth_headers" });
        }

        const bot = db.bots[botId];
        if (!bot) return res.status(401).json({ ok: false, error: "unknown_bot" });

        if (Math.abs(Date.now() - timestamp) > MAX_SKEW_MS) {
            return res.status(401).json({ ok: false, error: "stale_timestamp" });
        }

        if (db.nonces[nonce]) {
            return res.status(401).json({ ok: false, error: "replay_detected" });
        }

        const rawBody = req.rawBody || "";
        const expected = sign(bot.apiKeySecret, req.method, req.originalUrl.split("?")[0], timestamp, nonce, rawBody);
        if (!timingSafeEqual(signature, expected)) {
            return res.status(401).json({ ok: false, error: "bad_signature" });
        }

        if (rateLimited(botId, limitPerMinute)) {
            return res.status(429).json({ ok: false, error: "rate_limited" });
        }

        // نونس يُسجَّل فقط بعد قبول التوقيع فعلاً (منع استنزاف الذاكرة بطلبات مزيفة)
        db.nonces[nonce] = Date.now() + MAX_SKEW_MS;
        save();

        req.botId = botId;
        next();
    };
}

/** يُستخدم من سكربت إداري فقط لإنشاء بوت جديد (ليس عبر HTTP) */
function createBot(botId) {
    if (db.bots[botId]) throw new Error("bot_id_exists");
    const apiKeySecret = crypto.randomBytes(32).toString("hex");
    db.bots[botId] = { apiKeySecret, createdAt: Date.now() };
    save();
    return apiKeySecret;
}

module.exports = { verifyBot, sign, createBot };
