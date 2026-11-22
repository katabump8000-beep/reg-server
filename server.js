"use strict";
/**
 * server.js — المنصة المركزية لإدارة جلسات التسجيل وطلبات الانضمام لعدة بوتات واتساب.
 *
 * هذه المنصة لا تتصل بواتساب أبداً ولا تحتاج رقم واتساب خاصاً بها — هي خدمة HTTP خلفية
 * يستدعيها كل بوت (عبر bot-plugin/registration-client.js) بعد أن يكون قد التقط الحدث
 * الموثوق من Baileys بنفسه (ضغطة زر تفاعلي حقيقية، رسالة نصية فعلية، أو حدث انضمام فعلي).
 *
 * مهم جداً: هذا السيرفر لا يثق أبداً بأي "senderJid" يصل من المتصفح/صفحة HTML — فلا توجد
 * قناة كهذه أصلاً هنا. الهوية تصل فقط من البوت نفسه عبر حقل senderJid الذي يستخرجه البوت
 * من message.key.participant/remoteJid (مصدر Baileys الموثوق)، ويُوقَّع الطلب كله بمفتاح
 * البوت الخاص حتى لا يستطيع أي طرف غير البوت نفسه انتحال هذا الحقل.
 */

const express = require("express");
const crypto = require("crypto");
const { db, save } = require("./store");
const { verifyBot } = require("./auth");

const app = express();
app.disable("x-powered-by");

app.use(express.json({
    limit: "64kb",
    verify: (req, _res, buf) => { req.rawBody = buf.toString("utf8"); }
}));

const log = (...a) => console.log("[reg-server]", ...a);
const logErr = (...a) => console.error("[reg-server]", ...a);

const digits = (v) => String(v || "").replace(/\D/g, "");
const sessKey = (id) => id;
const codeKey = (botId, groupJid, code) => `${botId}|${groupJid}|${code}`;
const regKey = (botId, groupJid, number) => `${botId}|${groupJid}|${number}`;

// -------------------------------------------------------------
// GET /api/health — بدون توقيع، فقط للتأكد أن السيرفر حي
// -------------------------------------------------------------
app.get("/api/health", (req, res) => res.json({ ok: true, now: Date.now() }));

const auth = verifyBot({ limitPerMinute: 120 });

// -------------------------------------------------------------
// POST /api/sessions
// body: { groupJid, senderJid, ttlMs? }
// يُنشئ جلسة تسجيل مستقلة لكل ضاغط، مرتبطة بهويته الموثوقة (senderJid من البوت).
// -------------------------------------------------------------
app.post("/api/sessions", auth, (req, res) => {
    const botId = req.botId;
    const { groupJid, senderJid } = req.body || {};
    const ttlMs = Math.min(Math.max(Number(req.body?.ttlMs) || 10 * 60 * 1000, 30 * 1000), 60 * 60 * 1000);

    if (!groupJid || !senderJid) {
        return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    const senderNumber = digits(senderJid);
    if (!senderNumber) return res.status(400).json({ ok: false, error: "invalid_sender" });

    // جلسة سابقة معلّقة لنفس (البوت+الشات+الشخص) تُبطَل (جلسة واحدة فعالة لكل شخص)
    for (const [id, s] of Object.entries(db.sessions)) {
        if (s.botId === botId && s.groupJid === groupJid && s.senderNumber === senderNumber && s.status === "pending") {
            delete db.codeIndex[codeKey(botId, groupJid, s.code)];
            delete db.sessions[id];
        }
    }

    let code, tries = 0;
    do { code = String(Math.floor(100000 + Math.random() * 900000)); tries++; }
    while (db.codeIndex[codeKey(botId, groupJid, code)] && tries < 50);

    const sessionId = crypto.randomUUID();
    const flowToken = crypto.randomBytes(12).toString("hex");
    const now = Date.now();

    db.sessions[sessionId] = {
        sessionId, flowToken, botId, groupJid,
        senderJid: String(senderJid), senderNumber,
        code, status: "pending", used: false,
        createdAt: now, expiresAt: now + ttlMs
    };
    db.codeIndex[codeKey(botId, groupJid, code)] = sessionId;
    save();

    log(`جلسة جديدة بوت=${botId} شات=${groupJid} مرسل=${senderNumber} كود=${code}`);
    return res.json({ ok: true, sessionId, flowToken, code, expiresAt: db.sessions[sessionId].expiresAt });
});

// -------------------------------------------------------------
// GET /api/sessions/by-code?groupJid=&code=&senderJid=
// يتحقق البوت من صاحب كود أرسل بيانات حرة: هل الكود صالح، وهل المرسل هو نفسه صاحب الجلسة؟
// -------------------------------------------------------------
app.get("/api/sessions/by-code", auth, (req, res) => {
    const botId = req.botId;
    const { groupJid, code } = req.query;
    const senderJid = req.query.senderJid;
    if (!groupJid || !code || !senderJid) return res.status(400).json({ ok: false, error: "missing_fields" });

    const id = db.codeIndex[codeKey(botId, String(groupJid), String(code))];
    const s = id ? db.sessions[id] : null;

    if (!s || s.used || Date.now() > s.expiresAt) {
        return res.json({ ok: true, valid: false, reason: !s ? "not_found" : s.used ? "used" : "expired" });
    }

    const senderNumber = digits(senderJid);
    if (senderNumber !== s.senderNumber) {
        log(`⚠️ كود صحيح لكن مرسل مختلف: جلسة لـ${s.senderNumber}, وصل من ${senderNumber} (بوت ${botId})`);
        return res.json({ ok: true, valid: false, reason: "sender_mismatch" });
    }

    return res.json({ ok: true, valid: true, sessionId: s.sessionId, flowToken: s.flowToken });
});

// -------------------------------------------------------------
// POST /api/sessions/:id/submit
// body: { senderJid, data: {nickname, referrer, gender, age} }
// البوت هو من يتولى التحقق من قواعد اللقب/الألفاظ الممنوعة/العمر محلياً (لأنها مرتبطة بأعضاء
// قروبه هو تحديداً)، ثم يستدعي هذه النقطة فقط لتسجيل العملية مركزياً ومنع إعادة الاستخدام.
// -------------------------------------------------------------
app.post("/api/sessions/:id/submit", auth, (req, res) => {
    const botId = req.botId;
    const s = db.sessions[req.params.id];
    const { senderJid, data } = req.body || {};

    if (!s || s.botId !== botId) return res.status(404).json({ ok: false, error: "not_found" });
    if (s.used) return res.json({ ok: false, error: "already_used" });
    if (Date.now() > s.expiresAt) return res.json({ ok: false, error: "expired" });

    const senderNumber = digits(senderJid);
    if (senderNumber !== s.senderNumber) return res.status(403).json({ ok: false, error: "sender_mismatch" });

    if (!data || !data.nickname || !data.gender || !data.age) {
        return res.status(400).json({ ok: false, error: "missing_data" });
    }

    const rk = regKey(botId, s.groupJid, senderNumber);
    if (db.registrations[rk] && !db.registrations[rk].reset) {
        return res.json({ ok: false, error: "already_registered" });
    }

    db.registrations[rk] = {
        botId, groupJid: s.groupJid, senderJid: s.senderJid, senderNumber,
        nickname: String(data.nickname), referrer: String(data.referrer || ""),
        gender: String(data.gender), age: Number(data.age),
        registeredAt: Date.now(), used: false, joinApprovedAt: 0, welcomedAt: 0, reset: false
    };
    s.used = true; s.status = "completed";
    save();

    log(`✅ تسجيل مكتمل: ${data.nickname} (${senderNumber}) بوت=${botId} شات=${s.groupJid}`);
    return res.json({ ok: true });
});

// -------------------------------------------------------------
// POST /api/join-requests/check
// body: { groupJid, participantJid }
// يناديها البوت عند استقبال حدث "group.join-request" ليقرر: يوافق أم لا.
// -------------------------------------------------------------
app.post("/api/join-requests/check", auth, (req, res) => {
    const botId = req.botId;
    const { groupJid, participantJid } = req.body || {};
    if (!groupJid || !participantJid) return res.status(400).json({ ok: false, error: "missing_fields" });

    const number = digits(participantJid);
    const r = db.registrations[regKey(botId, groupJid, number)];

    if (!r) return res.json({ ok: true, approve: false, reason: "not_registered" });
    if (r.used) return res.json({ ok: true, approve: false, reason: "already_joined" });

    r.joinApprovedAt = Date.now();
    save();
    return res.json({ ok: true, approve: true, nickname: r.nickname });
});

// -------------------------------------------------------------
// POST /api/join-requests/confirm
// body: { groupJid, participantJid }
// يناديها البوت بعد تأكد فعلي أن العضو دخل القروب (group-participants.update: add) — قبل إرسال
// الترحيب — لمنع تكرار الترحيب عبر عدة نسخ من البوت أو بعد إعادة تشغيل.
// -------------------------------------------------------------
app.post("/api/join-requests/confirm", auth, (req, res) => {
    const botId = req.botId;
    const { groupJid, participantJid } = req.body || {};
    if (!groupJid || !participantJid) return res.status(400).json({ ok: false, error: "missing_fields" });

    const number = digits(participantJid);
    const r = db.registrations[regKey(botId, groupJid, number)];
    if (!r) return res.json({ ok: true, shouldWelcome: false, reason: "not_registered" });

    if (r.used && r.welcomedAt) {
        return res.json({ ok: true, shouldWelcome: false, reason: "already_welcomed" });
    }

    r.used = true;
    r.welcomedAt = Date.now();
    save();
    return res.json({ ok: true, shouldWelcome: true, nickname: r.nickname });
});

app.use((err, req, res, _next) => {
    logErr(err?.stack || err);
    res.status(500).json({ ok: false, error: "internal_error" });
});

const PORT = Number(process.env.PORT || 8787);
app.listen(PORT, () => log(`يستمع على المنفذ ${PORT}`));
