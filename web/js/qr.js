function loadJsQr() {
  if (window.jsQR) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/jsQR/1.4.0/jsQR.min.js';
    s.onload = resolve;
    s.onerror = () => reject(new Error('Could not load the QR reader. Check your connection and try again.'));
    document.head.appendChild(s);
  });
}

/** Reads a QR code from an image file. Uses the browser's built-in detector when present, else jsQR. */
export async function decodeQr(file) {
  const bitmap = await createImageBitmap(file);
  if ('BarcodeDetector' in window) {
    try {
      const found = await new window.BarcodeDetector({ formats: ['qr_code'] }).detect(bitmap);
      if (found[0]?.rawValue) return found[0].rawValue;
    } catch { /* fall through to jsQR */ }
  }
  await loadJsQr();
  const scale = Math.min(1, 1200 / Math.max(bitmap.width, bitmap.height));
  const w = Math.round(bitmap.width * scale), h = Math.round(bitmap.height * scale);
  const canvas = document.createElement('canvas');
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0, w, h);
  const code = window.jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
  return code?.data || null;
}
