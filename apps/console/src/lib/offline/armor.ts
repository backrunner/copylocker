/**
 * 离线激活门户的纯函数层：AR 输入解析与 CLK1 armor 归一化。
 *
 * 线格式权威：
 * - AR（激活请求）是 canonical CBOR 字节流（`copylocker offline request` 的产物），
 *   上限 16 KiB（copylocker-types `MAX_BODY_BYTES`）；服务端另有协议层解析上限。
 * - CLK1 armor 是 `CLK1:` 前缀的 Crockford Base32 文本，或 PEM 边界包裹形态
 *   （crates/copylocker-proto/src/offline_bundle.rs）。
 */

/** AR 请求体上限（copylocker-types `MAX_BODY_BYTES`）。 */
export const MAX_AR_BYTES = 16 * 1024;
/** 激活响应（AResp）下载上限（与 CLI `MAX_OFFLINE_RESPONSE_BYTES` 一致）。 */
export const MAX_ARESP_BYTES = 2 * 1024 * 1024;
/** CLK1 armor 字符上限（`MAX_OLK_BUNDLE_BYTES` 的两倍，与 CLI `read_armor` 一致）。 */
export const MAX_ARMOR_CHARS = 2 * 1024 * 1024;
/**
 * 单个 QR 码（version 40，纠错 M，alphanumeric 模式）实际可容纳的 armor 字符上限。
 * 超过即提示走文件传输，与 `copylocker offline qr` 的拒绝行为一致。
 */
export const MAX_QR_ARMOR_CHARS = 3_000;

const CROCKFORD = /^[0-9A-HJKM-NP-TV-Z]+$/;
const PEM_BEGIN = '-----BEGIN COPYLOCKER OFFLINE LICENSE-----';
const PEM_END = '-----END COPYLOCKER OFFLINE LICENSE-----';

function decodeHex(text: string): Uint8Array | null {
	if (text.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(text)) return null;
	const bytes = new Uint8Array(text.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

function decodeBase64(text: string): Uint8Array | null {
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) return null;
	try {
		const binary = atob(text);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
		return bytes;
	} catch {
		return null;
	}
}

/**
 * 解析粘贴的 AR 负载：hex（偶数长）或 base64。返回错误字符串或字节。
 * 字节上限 16 KiB；canonical CBOR 的完整校验在服务端进行（门户不重实现协议解析）。
 */
export function parseArPayload(text: string): { bytes: Uint8Array } | { error: string } {
	const compact = text.replace(/\s+/g, '');
	if (compact.length === 0) {
		return { error: '请输入激活请求（hex 或 base64），或上传请求文件' };
	}
	const bytes = decodeHex(compact) ?? decodeBase64(compact);
	if (!bytes) {
		return { error: '无法解析输入：只接受 hex 或 base64 文本' };
	}
	if (bytes.length === 0 || bytes.length > MAX_AR_BYTES) {
		return { error: `激活请求必须在 1 字节到 ${MAX_AR_BYTES} 字节之间` };
	}
	return { bytes };
}

/**
 * 归一化 CLK1 armor：接受紧凑形态（`CLK1:…`）或 PEM 边界形态，返回紧凑形态。
 * 与 `OfflineLicenseBundle::from_armored` 的接受面一致（字符集在此预检，
 * 真正的 CBOR 解码在离线设备的客户端里发生）。
 */
export function normalizeClk1Armor(text: string): { armor: string } | { error: string } {
	const trimmed = text.trim();
	if (trimmed.length === 0) {
		return { error: '请粘贴 CLK1 armor 文本' };
	}
	if (trimmed.length > MAX_ARMOR_CHARS) {
		return { error: `armor 超过 ${MAX_ARMOR_CHARS} 字符上限` };
	}
	let body: string;
	if (trimmed.startsWith('CLK1:')) {
		body = trimmed.slice('CLK1:'.length).replace(/\s+/g, '');
	} else if (trimmed.includes(PEM_BEGIN) && trimmed.includes(PEM_END)) {
		body = trimmed
			.replace(PEM_BEGIN, '')
			.replace(PEM_END, '')
			.replace(/\s+/g, '');
	} else {
		return { error: '不是有效的 CLK1 armor（需要 `CLK1:` 前缀或 PEM 边界）' };
	}
	if (body.length === 0 || !CROCKFORD.test(body)) {
		return { error: 'armor 含有 Crockford Base32 之外的字符' };
	}
	return { armor: `CLK1:${body}` };
}

/** armor 是否能装进单个 QR 码。 */
export function fitsInQr(armor: string): boolean {
	return armor.length <= MAX_QR_ARMOR_CHARS;
}
