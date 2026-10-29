// Adds demo community reports so the feed is not empty. Every entry is obviously fake (reserved/invalid names).
import { config } from '../config.js';
import { createDb, migrate } from './index.js';
import { uuid, nowIso } from '../lib/auth.js';

const db = await createDb(config);
await migrate(db);

const demo = [
  ['url', 'sbi-kyc-update.example-scam.xyz', 'Bank / KYC block', 'SMS said my account would be blocked in 2 hours unless I updated KYC.', 'verified', 14, 0],
  ['upi', 'refund.support@demoupi', 'Refund scam', 'Caller asked me to "accept a collect request" to receive a refund.', 'verified', 9, 1],
  ['phone', '+919000000001', 'Digital arrest / fake authority', 'Video call claiming to be CBI, asked me to stay on the line and transfer money.', 'pending', 5, 0],
  ['url', 'tneb-bill-pay.example-scam.top', 'Electricity / utility bill', 'Message: power will be cut tonight, call the number to pay.', 'pending', 4, 0],
  ['message', 'Earn Rs 5000 daily by liking videos. Join our Telegram group today.', 'Job or task scam', 'Came on WhatsApp from an unknown number.', 'pending', 3, 1],
];
let added = 0;
for (const [kind, value, category, description, status, confirms, disputes] of demo) {
  const exists = await db.get('SELECT id FROM reports WHERE kind = $1 AND value = $2', [kind, value]);
  if (exists) continue;
  const now = nowIso();
  await db.run('INSERT INTO reports (id, user_id, kind, value, category, description, status, confirms, disputes, created_at, updated_at) VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$9)',
    [uuid(), kind, value, category, description, status, confirms, disputes, now]);
  added++;
}
console.log(`Seeded ${added} demo reports.`);
await db.close();
