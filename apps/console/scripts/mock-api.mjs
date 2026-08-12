/**
 * 本地开发用的 Admin API mock（npm run mock，默认 :8788）。
 *
 * 覆盖 A 组页面用到的全部端点，内存态、带 CORS，配合
 * PUBLIC_API_BASE=http://localhost:8788 npm run dev 使用。
 * 只用于开发 —— 数据不持久、校验从简，真实语义以 API Worker 为准。
 */
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';

const PORT = Number(process.env.MOCK_PORT ?? 8788);

const now = () => Math.floor(Date.now() / 1000);
const hex = (bytes) =>
	Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, '0')).join('');

const state = {
	catalog: {
		version: 3,
		features: [
			{ id: 'export.pdf', label: 'PDF 导出' },
			{ id: 'export.png', label: 'PNG 导出' },
			{ id: 'ai.assist', label: 'AI 助手', description: '云端 AI 辅助能力' },
			{ id: 'render.4k', label: '4K 渲染' }
		],
		groups: [
			{ id: 'export', label: '导出包', members: { includes: [], features: ['export.*'] } }
		],
		tiers: [
			{ id: 'free', label: '免费版', rank: 0, groups: [], features: ['export.png'], limits: { 'render.max_dpi': 150 } },
			{ id: 'pro', label: '专业版', rank: 1, groups: ['export'], features: ['ai.assist'], limits: { 'render.max_dpi': 300 } },
			{ id: 'team', label: '团队版', rank: 2, groups: ['export'], features: ['ai.assist', 'render.4k'], limits: { 'render.max_dpi': 600 } }
		]
	},
	policies: [],
	licenses: [],
	epochs: [],
	releases: []
};

state.policies.push({
	id: 'sub-annual-pro',
	product_id: 'demo-app',
	name: '年度订阅 · 专业版',
	preset: 'sub-annual',
	entitlement: { tier: 'pro', extra_groups: [], grants: [], excluded_features: [], limit_overrides: {}, limit_merge: {} },
	validity: { kind: 'subscription', period_secs: 365 * 86400, dunning_grace_secs: 14 * 86400, fallback: null },
	version_scope: { kind: 'semver_range', value: '^3' },
	seats: { seats: 3, max_transfers: 6, transfer_window_secs: 30 * 86400, heartbeat_secs: 3600 },
	mode: 'offline_hybrid',
	runtime: {
		refresh_after_secs: 7 * 86400,
		grace_secs: 14 * 86400,
		fpr_tolerance: 60,
		allow_vm: true,
		allow_olk: true,
		allow_unbound_olk: false,
		vt_signature: 'fast',
		offline_upgrade_policy: 'preload_n',
		preload_variants_n: 2,
		report_attrs: true
	}
});

state.epochs.push({
	epoch_id: hex(8),
	product_id: 'demo-app',
	suite_id: hex(8),
	not_before: now() - 30 * 86400,
	not_after: now() + 335 * 86400,
	revoked_at: null,
	created_at: now() - 30 * 86400,
	status: 'active',
	affected_machines_upper_bound: 0
});

// Simulator 页面的版本决策输入（variant_params 永不在此投影出现）。
state.releases.push(
	{
		id: 'rel_38',
		product_id: 'demo-app',
		app_version: '3.8.0',
		variant_id: 38,
		build_fingerprint: hex(16),
		manifest_root_hex: null,
		channel: 'stable',
		status: 'active',
		compromised_action: null,
		published_at: now() - 60 * 86400,
		deprecated_at: null,
		created_at: now() - 60 * 86400
	},
	{
		id: 'rel_39',
		product_id: 'demo-app',
		app_version: '3.9.0',
		variant_id: 39,
		build_fingerprint: hex(16),
		manifest_root_hex: null,
		channel: 'stable',
		status: 'active',
		compromised_action: null,
		published_at: now() - 10 * 86400,
		deprecated_at: null,
		created_at: now() - 10 * 86400
	}
);

const error = (res, status, code, message) =>
	json(res, status, { ok: false, error: { code, message } });

function json(res, status, value) {
	res.writeHead(status, {
		'content-type': 'application/json',
		'cache-control': 'no-store',
		'access-control-allow-origin': '*'
	});
	res.end(JSON.stringify(value));
}

function resolveCatalog(entitlement) {
	const tiers = [...state.catalog.tiers].sort((a, b) => a.rank - b.rank);
	const tier = tiers.find((t) => t.id === entitlement.tier);
	if (!tier) return null;
	const features = new Set(tier.features ?? []);
	for (const groupId of tier.groups ?? []) {
		const group = state.catalog.groups.find((g) => g.id === groupId);
		for (const f of group?.members.features ?? []) {
			if (f.endsWith('.*')) {
				const prefix = f.slice(0, -1);
				for (const feat of state.catalog.features) if (feat.id.startsWith(prefix)) features.add(feat.id);
			} else features.add(f);
		}
	}
	for (const f of entitlement.excluded_features ?? []) features.delete(f);
	return {
		features: [...features].sort(),
		limits: { ...(tier.limits ?? {}), ...(entitlement.limit_overrides ?? {}) },
		tier_id: tier.id,
		tier_label: tier.label,
		catalog_version: state.catalog.version,
		version_scope: null,
		subscription_hint: null
	};
}

const routes = [];
const route = (method, pattern, fn) =>
	routes.push({ method, regex: new RegExp(`^${pattern.replace(/:([a-z_]+)/g, '(?<$1>[^/]+)')}$`), fn });

route('GET', '/v1/admin/licenses', (req, res, { query }) => {
	const productId = query.get('product_id');
	if (!productId) return error(res, 400, 'invalid_query', 'product_id is required');
	const status = query.get('status');
	const limit = Math.min(Number(query.get('limit') ?? 50), 100);
	let items = state.licenses.filter((l) => l.product_id === productId);
	if (status) items = items.filter((l) => l.status === status);
	json(res, 200, { ok: true, product_id: productId, items: items.slice(0, limit) });
});

route('GET', '/v1/admin/releases', (req, res, { query }) => {
	const productId = query.get('product_id');
	if (!productId) return error(res, 400, 'invalid_query', 'product_id is required');
	json(res, 200, {
		ok: true,
		product_id: productId,
		items: state.releases.filter((r) => r.product_id === productId)
	});
});

route('POST', '/v1/admin/licenses', (req, res, { body }) => {
	const count = Math.min(body.count ?? 1, 100);
	const licenses = Array.from({ length: count }, () => {
		const id = hex(16);
		const record = {
			license_id: id,
			product_id: body.product_id,
			policy_id: body.policy_id,
			account_id: body.account_id ?? null,
			status: 'active',
			seats_override: body.seats_override ?? null,
			entitlement_override: null,
			version_scope_override: null,
			expires_at: body.expires_at ?? null,
			catalog_version: state.catalog.version,
			metadata: body.metadata ?? null,
			created_at: now(),
			updated_at: now(),
			seats_used: 0,
			last_seen_at: null
		};
		state.licenses.push(record);
		return { license_id: id, license_key: `CLK1-DEMO-${hex(4).toUpperCase()}-${hex(4).toUpperCase()}` };
	});
	json(res, 201, {
		ok: true,
		product_id: body.product_id,
		policy_id: body.policy_id,
		catalog_version: state.catalog.version,
		count,
		license_ids: licenses.map((l) => l.license_id),
		licenses
	});
});

route('GET', '/v1/admin/licenses/:id', (req, res, { groups }) => {
	const license = state.licenses.find((l) => l.license_id === groups.id);
	if (!license) return error(res, 404, 'not_found', 'license not found');
	json(res, 200, { ok: true, license });
});

route('PATCH', '/v1/admin/licenses/:id', (req, res, { groups, body }) => {
	const license = state.licenses.find((l) => l.license_id === groups.id);
	if (!license) return error(res, 404, 'not_found', 'license not found');
	if (license.status === 'revoked') return error(res, 409, 'already_revoked', 'a revoked license cannot be changed');
	if (body.status) license.status = body.status;
	if (body.extend_by_seconds && license.expires_at) license.expires_at += body.extend_by_seconds;
	if (body.seats_override) license.seats_override = body.seats_override;
	license.updated_at = now();
	json(res, 200, { ok: true, license, version: 2 });
});

route('POST', '/v1/admin/licenses/:id/change-tier', (req, res, { groups, body }) => {
	const license = state.licenses.find((l) => l.license_id === groups.id);
	if (!license) return error(res, 404, 'not_found', 'license not found');
	if (!state.catalog.tiers.some((t) => t.id === body.tier))
		return error(res, 422, 'invalid_entitlement', `unknown tier \`${body.tier}\``);
	license.entitlement_override = { ...(license.entitlement_override ?? {}), tier: body.tier };
	license.updated_at = now();
	json(res, 200, { ok: true, license, version: 2 });
});

route('GET', '/v1/admin/licenses/:id/preview-fallback', (req, res, { groups }) => {
	if (!state.licenses.some((l) => l.license_id === groups.id))
		return error(res, 404, 'not_found', 'license not found');
	json(res, 200, {
		ok: true,
		license_id: groups.id,
		current_state: 'active',
		end_state: 'perpetual_fallback',
		version_cutoff: now(),
		fallback_earned_at: now() - 400 * 86400,
		continuous_paid_months: 14
	});
});

route('GET', '/v1/admin/licenses/:id/machines', (req, res, { groups }) => {
	if (!state.licenses.some((l) => l.license_id === groups.id))
		return error(res, 404, 'not_found', 'license not found');
	json(res, 200, {
		ok: true,
		license_id: groups.id,
		items: [
			{
				machine_id: hex(16),
				status: 'active',
				activation_path: 'online',
				first_seen_at: now() - 20 * 86400,
				last_seen_at: now() - 3600,
				os: 'macos',
				arch: 'arm64',
				app_version: '3.2.1',
				sdk_version: '0.9.0',
				release_id: null,
				variant_id: null,
				build_fingerprint: hex(16),
				geo_country: 'CN',
				suspicion: 0
			}
		]
	});
});

route('POST', '/v1/admin/:kind/:id/revoke', (req, res, { groups, query }) => {
	const dryRun = query.get('dry_run') !== 'false';
	if (dryRun) {
		return json(res, 200, {
			ok: true,
			dry_run: true,
			kind: groups.kind === 'machines' ? 'machine' : 'license',
			target: groups.id,
			affected_machines: 3,
			already_revoked: false
		});
	}
	const license = state.licenses.find((l) => l.license_id === groups.id);
	if (license) license.status = 'revoked';
	json(res, 200, {
		ok: true,
		dry_run: false,
		kind: groups.kind === 'machines' ? 'machine' : 'license',
		target: groups.id,
		revocation_epoch: 7
	});
});

for (const collection of ['features', 'groups', 'tiers']) {
	route('GET', `/v1/admin/catalog/${collection}`, (req, res, { query }) =>
		json(res, 200, {
			ok: true,
			product_id: query.get('product_id'),
			catalog_version: state.catalog.version,
			items: state.catalog[collection]
		})
	);
	const write = (create) => (req, res, { body }) => {
		const items = state.catalog[collection];
		const index = items.findIndex((item) => item.id === body.id);
		if (create && index >= 0) return error(res, 409, 'already_exists', 'catalog item already exists');
		if (!create && index < 0) return error(res, 404, 'not_found', 'catalog item not found');
		if (!create) {
			// 模拟 422 不可变护栏：重命名已发布 feature（演示用：id 以 export. 开头视为已发布）
			const before = items[index];
			if (collection === 'features' && before.id !== body.id && before.id.startsWith('export.')) {
				return error(
					res,
					422,
					'invalid_catalog',
					`feature \`${before.id}\` was published and cannot be renamed or removed; assets sealed under it would become unopenable`
				);
			}
		}
		const { product_id: _omit, ...item } = body;
		if (create) items.push(item);
		else items[index] = item;
		state.catalog.version += 1;
		json(res, create ? 201 : 200, {
			ok: true,
			product_id: body.product_id,
			catalog_version: state.catalog.version,
			item
		});
	};
	route('POST', `/v1/admin/catalog/${collection}`, write(true));
	route('PATCH', `/v1/admin/catalog/${collection}`, write(false));
}

route('POST', '/v1/admin/catalog/resolve', (req, res, { body }) => {
	const resolved = resolveCatalog(body.entitlement);
	if (!resolved) return error(res, 422, 'invalid_entitlement', `unknown tier \`${body.entitlement.tier}\``);
	json(res, 200, {
		ok: true,
		product_id: body.product_id,
		catalog_version: state.catalog.version,
		at: body.at ?? now(),
		entitlements: resolved
	});
});

route('GET', '/v1/admin/policies', (req, res, { query }) =>
	json(res, 200, {
		ok: true,
		product_id: query.get('product_id'),
		items: state.policies.filter((p) => p.product_id === query.get('product_id'))
	})
);
route('GET', '/v1/admin/policies/:id', (req, res, { groups }) => {
	const policy = state.policies.find((p) => p.id === groups.id);
	if (!policy) return error(res, 404, 'not_found', 'policy not found');
	json(res, 200, { ok: true, policy, version: 1, warnings: [] });
});
const writePolicy = (res, body, status) => {
	const index = state.policies.findIndex((p) => p.id === body.id);
	if (index >= 0) state.policies[index] = body;
	else state.policies.push(body);
	const warnings = [];
	if (body.validity?.kind === 'perpetual' && body.mode === 'enforced_online')
		warnings.push({
			id: 'perpetual_requires_forever_server',
			message: 'a perpetual licence in enforced-online mode stops working if the licence server is ever shut down'
		});
	if (body.runtime?.allow_unbound_olk)
		warnings.push({ id: 'unbound_olk_copyable', message: 'offline keys without a device binding can be copied without limit' });
	json(res, status, { ok: true, policy: body, version: 1, warnings });
};
route('POST', '/v1/admin/policies', (req, res, { body }) => writePolicy(res, body, 201));
route('PATCH', '/v1/admin/policies/:id', (req, res, { body }) => writePolicy(res, body, 200));

route('GET', '/v1/admin/epochs', (req, res, { query }) =>
	json(res, 200, {
		ok: true,
		product_id: query.get('product_id'),
		items: state.epochs.filter((e) => e.product_id === query.get('product_id'))
	})
);
route('GET', '/v1/admin/epochs/:id', (req, res, { groups }) => {
	const epoch = state.epochs.find((e) => e.epoch_id === groups.id);
	if (!epoch) return error(res, 404, 'not_found', 'epoch not found');
	json(res, 200, { ok: true, epoch, replacement_ready: true, replacement_epoch_ids: [] });
});
route('POST', '/v1/admin/epochs/:id/revoke', (req, res, { groups, query, body }) => {
	const epoch = state.epochs.find((e) => e.epoch_id === groups.id);
	if (!epoch) return error(res, 404, 'not_found', 'epoch not found');
	if (query.get('dry_run') !== 'false') {
		return json(res, 200, {
			ok: true,
			dry_run: true,
			epoch,
			affected_machines_upper_bound: epoch.affected_machines_upper_bound,
			replacement_ready: true,
			replacement_epoch_ids: [],
			already_revoked: epoch.revoked_at !== null,
			requires_distinct_actors: 2
		});
	}
	if (body.confirm_epoch_id !== groups.id)
		return error(res, 409, 'confirmation_mismatch', 'confirm_epoch_id does not match the target epoch');
	json(res, 202, {
		ok: true,
		dry_run: false,
		approval_pending: true,
		epoch_id: groups.id,
		first_actor: 'mock-admin',
		approval_expires_at: now() + 900,
		required_confirmations: 2,
		received_confirmations: 1
	});
});

createServer((req, res) => {
	if (req.method === 'OPTIONS') {
		res.writeHead(204, {
			'access-control-allow-origin': '*',
			'access-control-allow-methods': 'GET, POST, PATCH, OPTIONS',
			'access-control-allow-headers': 'authorization, content-type, idempotency-key',
			'access-control-max-age': '86400'
		});
		return res.end();
	}
	const url = new URL(req.url ?? '/', 'http://mock.invalid');
	const auth = req.headers.authorization ?? '';
	if (!/^Bearer clat_[A-Za-z0-9_-]{43}$/.test(auth))
		return error(res, 401, 'invalid_token', 'a valid Admin bearer token is required');
	const chunks = [];
	req.on('data', (chunk) => chunks.push(chunk));
	req.on('end', () => {
		let body = {};
		if (chunks.length) {
			try {
				body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
			} catch {
				return error(res, 400, 'invalid_request', 'request body must be a JSON object');
			}
		}
		const matched = routes.find((r) => r.method === req.method && r.regex.test(url.pathname));
		if (!matched) return error(res, 404, 'not_found', 'admin route not found');
		const groups = matched.regex.exec(url.pathname)?.groups ?? {};
		matched.fn(req, res, { query: url.searchParams, body, groups });
	});
}).listen(PORT, () => {
	console.log(`mock admin api listening on http://localhost:${PORT}`);
	console.log('token: 任意 clat_ + 43 位 base64url 字符');
});
