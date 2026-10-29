import test from 'node:test';
import assert from 'node:assert/strict';
import { scan, detectKind } from '../server/engine/index.js';

const run = (s) => scan(s);

test('detects input kinds', () => {
  assert.equal(detectKind('https://example.com/a'), 'url');
  assert.equal(detectKind('bit.ly/abc'), 'url');
  assert.equal(detectKind('rahul@oksbi'), 'upi');
  assert.equal(detectKind('upi://pay?pa=a@ybl'), 'upi');
  assert.equal(detectKind('+91 98765 43210'), 'phone');
  assert.equal(detectKind('please call me back'), 'message');
});

test('flags brand-impersonating link as dangerous', async () => {
  const r = await run('http://sbi-kyc-update.xyz/login');
  assert.equal(r.verdict, 'dangerous');
  assert.ok(r.signals.some((s) => s.id === 'brand_impersonation'));
});

test('official domain stays safe, and the trick @ link does not', async () => {
  assert.equal((await run('https://www.sbi.co.in/web/personal-banking')).verdict, 'safe');
  assert.notEqual((await run('https://www.sbi.co.in@evil-site.top/login')).verdict, 'safe');
});

test('catches look-alike domains', async () => {
  const r = await run('https://paypa1.com/signin');
  assert.ok(['suspicious', 'dangerous'].includes(r.verdict));
});

test('raw IP and apk downloads are flagged', async () => {
  assert.notEqual((await run('http://192.168.4.7/verify/otp')).verdict, 'safe');
  assert.equal((await run('https://files.example.org/pm-kisan.apk')).verdict !== 'safe', true);
});

test('KYC scam SMS is dangerous and highlights text', async () => {
  const r = await run('Dear customer your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login');
  assert.equal(r.verdict, 'dangerous');
  assert.ok(r.highlights.length >= 2);
  assert.equal(r.urls.length, 1);
});

test('genuine OTP notice is not flagged', async () => {
  const r = await run('482913 is your OTP for txn of Rs 500 at Amazon. Do not share OTP with anyone. -HDFC Bank');
  assert.equal(r.verdict, 'safe');
  assert.equal(r.score, 0);
});

test('ordinary chat is safe', async () => {
  assert.equal((await run('Hi, are we still meeting for lunch tomorrow at 1?')).verdict, 'safe');
});

test('digital arrest and remote access are caught', async () => {
  const r = await run('CBI officer here. A parcel in your name has drugs, you face digital arrest. Install AnyDesk now.');
  assert.equal(r.verdict, 'dangerous');
});

test('UPI refund-desk id and collect link are flagged', async () => {
  assert.notEqual((await run('refund.support@okaxis')).verdict, 'safe');
  assert.notEqual((await run('upi://collect?pa=help@upi&am=5000')).verdict, 'safe');
  assert.equal((await run('rahul@oksbi')).verdict, 'safe');
});

test('Hindi message is understood', async () => {
  const r = await run('आपका खाता बंद हो जाएगा, तुरंत केवाईसी अपडेट करें');
  assert.equal(r.language, 'Hindi');
  assert.notEqual(r.verdict, 'safe');
});

test('unreported phone number is unknown, not safe', async () => {
  assert.equal((await run('+91 98765 43210')).verdict, 'unknown');
});
