import { describe, expect, it } from 'vitest';
import {
	fitsInQr,
	MAX_AR_BYTES,
	normalizeClk1Armor,
	parseArPayload
} from './armor';

describe('parseArPayload', () => {
	it('parses lowercase hex', () => {
		const result = parseArPayload('a4 01 02');
		expect(result).toEqual({ bytes: new Uint8Array([0xa4, 0x01, 0x02]) });
	});

	it('parses base64', () => {
		const result = parseArPayload('pAEC');
		expect(result).toEqual({ bytes: new Uint8Array([0xa4, 0x01, 0x02]) });
	});

	it('rejects empty input', () => {
		expect(parseArPayload('   ')).toHaveProperty('error');
	});

	it('rejects non-hex non-base64 text', () => {
		expect(parseArPayload('not-a-payload!!')).toHaveProperty('error');
	});

	it('enforces the 16 KiB cap', () => {
		const oversized = 'ab'.repeat(MAX_AR_BYTES + 1);
		expect(parseArPayload(oversized)).toHaveProperty('error');
		const atCap = 'ab'.repeat(MAX_AR_BYTES);
		expect(parseArPayload(atCap)).toHaveProperty('bytes');
	});
});

describe('normalizeClk1Armor', () => {
	const compact = 'CLK1:0123456789ABCDEFGHJKMNPQRSTVWXYZ';

	it('accepts compact armor', () => {
		expect(normalizeClk1Armor(compact)).toEqual({ armor: compact });
	});

	it('accepts PEM-bounded armor and normalizes to compact', () => {
		const pem = `-----BEGIN COPYLOCKER OFFLINE LICENSE-----\n0123456789ABCDEFGHJKMNPQRSTVWXYZ\n-----END COPYLOCKER OFFLINE LICENSE-----\n`;
		expect(normalizeClk1Armor(pem)).toEqual({ armor: compact });
	});

	it('rejects text without the CLK1 prefix or PEM boundaries', () => {
		expect(normalizeClk1Armor('0123456789')).toHaveProperty('error');
	});

	it('rejects characters outside the Crockford alphabet', () => {
		expect(normalizeClk1Armor('CLK1:0123LOIU')).toHaveProperty('error');
	});

	it('rejects empty armor bodies', () => {
		expect(normalizeClk1Armor('CLK1:')).toHaveProperty('error');
	});
});

describe('fitsInQr', () => {
	it('bounds the QR payload like the CLI', () => {
		expect(fitsInQr('CLK1:' + 'A'.repeat(2_995))).toBe(true);
		expect(fitsInQr('CLK1:' + 'A'.repeat(3_000))).toBe(false);
	});
});
