// Reference data for the detection engine. Extend these lists freely.

export const CATEGORIES = [
  'Phishing link', 'Bank / KYC block', 'OTP / PIN theft', 'UPI collect request', 'Fake prize or lottery',
  'Job or task scam', 'Digital arrest / fake authority', 'Parcel or courier', 'Electricity / utility bill',
  'Remote-access app', 'Fake app (APK)', 'Investment or crypto', 'Refund scam', 'Other',
];

// Official domains per brand. A link on one of these domains (over https) gets a "known official site" note.
export const BRANDS = [
  { name: 'State Bank of India', keys: ['sbi', 'onlinesbi', 'yono'], domains: ['sbi.co.in', 'onlinesbi.sbi', 'sbicard.com', 'sbi.bank.in'] },
  { name: 'HDFC Bank', keys: ['hdfc', 'hdfcbank'], domains: ['hdfcbank.com', 'hdfcbank.bank.in'] },
  { name: 'ICICI Bank', keys: ['icici', 'icicibank'], domains: ['icicibank.com', 'icicibank.bank.in'] },
  { name: 'Axis Bank', keys: ['axisbank', 'axis'], domains: ['axisbank.com', 'axis.bank.in'] },
  { name: 'Kotak Mahindra Bank', keys: ['kotak'], domains: ['kotak.com', 'kotak.bank.in'] },
  { name: 'Punjab National Bank', keys: ['pnbindia', 'pnb'], domains: ['pnbindia.in', 'pnb.bank.in'] },
  { name: 'Indian Bank', keys: ['indianbank'], domains: ['indianbank.in', 'indianbank.net.in'] },
  { name: 'Paytm', keys: ['paytm'], domains: ['paytm.com', 'paytmbank.com'] },
  { name: 'PhonePe', keys: ['phonepe'], domains: ['phonepe.com'] },
  { name: 'Google', keys: ['google', 'gpay'], domains: ['google.com', 'google.co.in', 'gmail.com', 'googleapis.com', 'googleusercontent.com', 'gstatic.com', 'youtube.com'] },
  { name: 'NPCI / BHIM', keys: ['npci', 'bhim'], domains: ['npci.org.in', 'bhimupi.org.in'] },
  { name: 'Amazon', keys: ['amazon'], domains: ['amazon.in', 'amazon.com', 'amazon.co.uk', 'amzn.in', 'amzn.to', 'amazonaws.com', 'media-amazon.com'] },
  { name: 'Flipkart', keys: ['flipkart'], domains: ['flipkart.com', 'fkrt.it'] },
  { name: 'IRCTC', keys: ['irctc'], domains: ['irctc.co.in', 'irctc.com'] },
  { name: 'India Post', keys: ['indiapost'], domains: ['indiapost.gov.in'] },
  { name: 'UIDAI (Aadhaar)', keys: ['uidai', 'aadhaar'], domains: ['uidai.gov.in'] },
  { name: 'Income Tax Department', keys: ['incometax', 'incometaxindia'], domains: ['incometax.gov.in', 'incometaxindia.gov.in'] },
  { name: 'EPFO', keys: ['epfindia', 'epfo'], domains: ['epfindia.gov.in'] },
  { name: 'TANGEDCO / TNEB', keys: ['tangedco', 'tneb'], domains: ['tangedco.gov.in', 'tnebnet.org'] },
  { name: 'Reliance Jio', keys: ['jio'], domains: ['jio.com'] },
  { name: 'Airtel', keys: ['airtel'], domains: ['airtel.in', 'airtel.com'] },
  { name: 'PayPal', keys: ['paypal'], domains: ['paypal.com'] },
  { name: 'Microsoft', keys: ['microsoft', 'office365'], domains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'] },
  { name: 'Apple', keys: ['apple', 'icloud'], domains: ['apple.com', 'icloud.com'] },
  { name: 'Netflix', keys: ['netflix'], domains: ['netflix.com'] },
  { name: 'Meta (Facebook / Instagram / WhatsApp)', keys: ['facebook', 'instagram', 'whatsapp'], domains: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com', 'fb.com'] },
  { name: 'DHL', keys: ['dhl'], domains: ['dhl.com'] },
  { name: 'FedEx', keys: ['fedex'], domains: ['fedex.com'] },
  { name: 'Delhivery', keys: ['delhivery'], domains: ['delhivery.com'] },
  { name: 'Blue Dart', keys: ['bluedart'], domains: ['bluedart.com'] },
];

export const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'click', 'link', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'support', 'rest', 'country',
  'kim', 'loan', 'men', 'icu', 'buzz', 'cyou', 'sbs', 'monster', 'cfd', 'vip', 'live', 'cam', 'bid', 'win', 'stream',
]);

export const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc',
  'rebrand.ly', 's.id', 'bit.do', 'lnkd.in', 'buff.ly', 'v.gd', 'qr.ae', 'shorturl.asia',
]);

// Two-level public suffixes, so "login.sbi.co.in" is read as the site "sbi.co.in".
export const SECOND_LEVEL_SUFFIXES = new Set([
  'co.in', 'gov.in', 'org.in', 'net.in', 'ac.in', 'nic.in', 'res.in', 'edu.in', 'firm.in', 'gen.in', 'ind.in',
  'bank.in', 'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'com.br', 'co.za',
  'co.jp', 'com.sg', 'com.my', 'com.pk', 'com.bd', 'com.lk', 'co.id', 'com.ph', 'com.ng',
]);

export const RISKY_WORDS = [
  'login', 'signin', 'verify', 'verification', 'secure', 'update', 'kyc', 'account', 'wallet', 'bonus', 'claim',
  'refund', 'suspend', 'unlock', 'confirm', 'otp', 'reward', 'prize', 'gift', 'cashback', 'offer', 'free', 'recover',
];

export const RISKY_EXTENSIONS = [
  { ext: '.apk', weight: 40, label: 'Links to an Android app file (.apk)' },
  { ext: '.exe', weight: 30, label: 'Links to a Windows program (.exe)' },
  { ext: '.scr', weight: 30, label: 'Links to a screensaver/program file (.scr)' },
  { ext: '.msi', weight: 30, label: 'Links to a Windows installer (.msi)' },
  { ext: '.bat', weight: 30, label: 'Links to a script file (.bat)' },
  { ext: '.jar', weight: 25, label: 'Links to a Java program (.jar)' },
  { ext: '.zip', weight: 15, label: 'Links to a compressed download (.zip)' },
];

export const TLD_FOR_BARE_DOMAINS = [
  'com', 'in', 'net', 'org', 'co', 'io', 'xyz', 'top', 'click', 'link', 'info', 'biz', 'me', 'app', 'site', 'online',
  'live', 'vip', 'shop', 'store', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'support', 'cyou', 'sbs', 'icu', 'buzz',
  'zip', 'mov', 'ly', 'gl', 'is', 'gd', 'ws', 'to', 'gov', 'edu', 'bank', 'cam', 'win', 'bid',
];

// UPI handles run by banks and payment apps. Not exhaustive; unknown handles are a mild signal only.
export const UPI_HANDLES = new Set([
  'okhdfcbank', 'okicici', 'oksbi', 'okaxis', 'ybl', 'ibl', 'axl', 'paytm', 'pthdfc', 'ptyes', 'ptsbi', 'ptaxis',
  'apl', 'upi', 'sbi', 'icici', 'hdfcbank', 'axisbank', 'pnb', 'boi', 'cnrb', 'unionbank', 'unionbankofindia',
  'kotak', 'yesbank', 'yesbankltd', 'indus', 'idfcbank', 'idfcfirst', 'federal', 'fbl', 'rbl', 'aubank', 'ikwik',
  'freecharge', 'jupiteraxis', 'fam', 'slc', 'abfspay', 'airtel', 'postbank', 'ezeepay', 'cmsidfc', 'dbs',
  'sib', 'kvb', 'tmb', 'uco', 'iob', 'psb', 'barodampay', 'allbank', 'canarabank', 'centralbank', 'indianbank',
  'jsbp', 'mahb', 'cboi', 'ubi', 'pingpay', 'waicici', 'wahdfcbank', 'waaxis', 'wasbi', 'jio', 'naviaxis',
]);
