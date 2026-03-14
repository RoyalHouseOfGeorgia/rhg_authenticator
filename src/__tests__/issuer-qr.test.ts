import { describe, it, expect } from 'vitest';
import QRCode from 'qrcode';
import jsQR from 'jsqr';
import { createCanvas, loadImage } from 'canvas';

describe('QR encode/decode round-trip', () => {
  it('round-trips a verification URL through QR encode and decode', async () => {
    const url =
      'https://verify.royalhouseofgeorgia.ge/?p=eyJ2ZXJzaW9uIjoxLCJhdXRob3JpdHkiOiJUZXN0In0&s=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    const pngBuffer = await QRCode.toBuffer(url, {
      errorCorrectionLevel: 'Q',
      version: 24,
      width: 512,
      margin: 4,
    });

    // Decode the PNG
    const image = await loadImage(pngBuffer);
    const canvas = createCanvas(image.width, image.height);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(image, 0, 0);
    const imageData = ctx.getImageData(0, 0, image.width, image.height);
    const result = jsQR(
      new Uint8ClampedArray(imageData.data.buffer),
      imageData.width,
      imageData.height,
    );

    expect(result).not.toBeNull();
    expect(result!.data).toBe(url);
  });

  it('QR version 24-Q succeeds at 661 bytes (byte mode)', () => {
    // Lowercase forces byte mode (not alphanumeric), matching real URL data
    const data = 'a'.repeat(661);
    expect(() => {
      QRCode.create(data, {
        errorCorrectionLevel: 'Q',
        version: 24,
      });
    }).not.toThrow();
  });

  it('QR version 24-Q fails at 662 bytes (byte mode)', () => {
    const data = 'a'.repeat(662);
    expect(() => {
      QRCode.create(data, {
        errorCorrectionLevel: 'Q',
        version: 24,
      });
    }).toThrow();
  });

  it('short data with version 24 still produces 113x113 modules', () => {
    const qr = QRCode.create('hello', {
      errorCorrectionLevel: 'Q',
      version: 24,
    });
    expect(qr.modules.size).toBe(113);
  });

  it('toBuffer with width 2048 produces a valid PNG with expected dimensions', async () => {
    const url = 'https://verify.royalhouseofgeorgia.ge/?p=test&s=test';
    const pngBuffer = await QRCode.toBuffer(url, {
      errorCorrectionLevel: 'Q',
      version: 24,
      width: 2048,
      margin: 4,
    });

    // Verify it's a valid PNG (magic bytes)
    expect(pngBuffer[0]).toBe(0x89);
    expect(pngBuffer[1]).toBe(0x50); // P
    expect(pngBuffer[2]).toBe(0x4e); // N
    expect(pngBuffer[3]).toBe(0x47); // G

    // Load and check dimensions
    const image = await loadImage(pngBuffer);
    expect(image.width).toBe(2048);
    expect(image.height).toBe(2048);
  });
});
