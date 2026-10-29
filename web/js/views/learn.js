import { html, mount } from '../ui.js';

const PLAYBOOKS = [
  { t: 'Digital arrest', how: 'A caller says they are from CBI, customs, police or TRAI. They claim a parcel in your name has drugs or your number is linked to crime, then keep you on a video call and demand money to "clear" your name.',
    flags: ['Any "arrest" over a phone or video call', 'Told not to hang up or tell anyone', 'Asked to move money to a "safe" or "RBI" account'], act: 'Hang up. No agency arrests people online or takes money to close a case. Call 1930.' },
  { t: 'KYC and account-block messages', how: 'An SMS or WhatsApp says your bank account, SIM or wallet will be blocked unless you update KYC through a link.',
    flags: ['A link to a site that is not your bank\'s exact address', 'A deadline of hours', 'A request for card details or OTP'], act: 'Open your bank\'s app yourself, or call the number on the back of your card.' },
  { t: 'UPI "refund" and collect requests', how: 'Someone says they will send you money, a refund or a deposit. They ask you to approve a request or scan a code, and enter your UPI PIN.',
    flags: ['"Enter your PIN to receive money"', 'A payment request you did not start', 'A QR code you are told to scan to get paid'], act: 'You never enter a PIN to receive money. Decline the request and block the number.' },
  { t: 'Fake electricity and utility bills', how: 'A message says your power will be cut tonight because of an unpaid bill, and gives a number to call or a link to pay.',
    flags: ['Disconnection "tonight"', 'A personal mobile number to call', 'A payment link that is not the utility\'s site'], act: 'Check your bill on the utility\'s official app or website, or visit the office.' },
  { t: 'Task and part-time job scams', how: 'You get a message offering money for liking videos or rating products. Early payouts are small and real. Then you are asked to "invest" to unlock bigger tasks.',
    flags: ['Contact from an unknown number on WhatsApp or Telegram', 'Pay first, earn later', 'Pressure to deposit more to withdraw'], act: 'A real job never asks you to pay. Stop and do not add more money.' },
  { t: 'Fake apps (APK files)', how: 'A link asks you to install an app to claim a scheme, update KYC or see a "wedding invitation". The app reads your SMS and OTPs or lets the scammer control your phone.',
    flags: ['A file ending in .apk sent in chat', 'An app not on Google Play', 'Asks for SMS, accessibility or screen-sharing permission'], act: 'If you installed one, switch on flight mode, uninstall it and call your bank.' },
  { t: 'Parcel and courier messages', how: 'A courier says your parcel is held for a missing address or a small fee. The link asks for card details.',
    flags: ['You are not expecting a parcel', 'A small fee on an unfamiliar site', 'Courier name with an odd web address'], act: 'Track parcels only in the shop or courier\'s own app.' },
  { t: 'Investment and trading groups', how: 'You are added to a group where "experts" share screenshots of huge profits and push you into a trading app that shows fake gains.',
    flags: ['Guaranteed returns', 'Added to a group without asking', 'Withdrawals blocked unless you pay a "tax"'], act: 'Check any adviser or platform on the SEBI website before sending money.' },
];

export async function render(el) {
  mount(el, html`
    <section class="page">
      <h1 class="h-lg">How these scams work</h1>
      <p class="lede sm">Eight patterns cover most of what people report. Learn the shape, and you will spot new versions too.</p>
      <div class="playbooks">
        ${PLAYBOOKS.map((p, i) => html`
        <details ${i === 0 ? 'open' : ''}>
          <summary>${p.t}</summary>
          <p>${p.how}</p>
          <h3 class="h-xs">Red flags</h3>
          <ul>${p.flags.map((f) => html`<li>${f}</li>`)}</ul>
          <h3 class="h-xs">What to do</h3>
          <p>${p.act}</p>
        </details>`)}
      </div>
      <aside class="help-box">
        <h2 class="h-sm">If you already lost money</h2>
        <ol>
          <li>Call your bank right away and ask them to block the card or account and flag the transfer.</li>
          <li>Call <strong>1930</strong>, the National Cyber Crime Helpline, or file a report at <strong>cybercrime.gov.in</strong>. The sooner you report, the better the chance of freezing the money.</li>
          <li>Report the number or message at <strong>sancharsaathi.gov.in</strong> so it can be blocked.</li>
          <li>Change passwords and UPI PINs, and remove any app you were told to install.</li>
        </ol>
      </aside>
    </section>`);
}
