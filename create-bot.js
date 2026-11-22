"use strict";
/**
 * سكربت إداري: ينشئ بوتاً جديداً على المنصة ويطبع مفتاح API الخاص به مرة واحدة فقط.
 * الاستخدام:
 *   node create-bot.js bot1
 */
const { createBot } = require("./auth");

const botId = process.argv[2];
if (!botId) {
    console.error("الاستخدام: node create-bot.js <bot-id>");
    process.exit(1);
}

try {
    const key = createBot(botId);
    console.log("✅ تم إنشاء البوت:", botId);
    console.log("🔑 احفظ هذا المفتاح الآن (لن يُعرض مجدداً) وضعه في متغير REGISTRATION_API_KEY لهذا البوت:");
    console.log(key);
} catch (e) {
    console.error("❌ فشل:", e.message);
    process.exit(1);
}
