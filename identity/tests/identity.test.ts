import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { Admission } from "../src/admission.js";
import { IdentityClient } from "../src/client.js";
import { HttpProvider, createProviderHandler } from "../src/provider.js";
import { SqliteIdentityStore, SqliteJournal } from "../src/sqlite.js";
import {
	RULE_VERSION,
	type AuditEvent,
	type Provider,
} from "../src/contracts.js";

const cleanups: (() => void)[] = [];
afterEach(() => {
	for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});
const origin = "https://identity.test",
	merchantOrigin = "https://seller.test";
const partnerToken = "partner-test-token-".repeat(3),
	adminToken = "admin-test-token-".repeat(3);
function setup() {
	const directory = mkdtempSync(join(tmpdir(), "aithos-identity-test-"));
	cleanups.push(() => rmSync(directory, { recursive: true }));
	const store = new SqliteIdentityStore(join(directory, "provider.sqlite"));
	const journal = new SqliteJournal(join(directory, "outbox.sqlite"));
	cleanups.push(
		() => store.close(),
		() => journal.close(),
	);
	const handler = createProviderHandler({
		origin,
		store,
		partners: [
			{ merchantId: "shop", token: partnerToken },
			{ merchantId: "other", token: "other-partner-".repeat(4) },
		],
		adminToken,
	});
	const transport: typeof fetch = Object.assign(
		(input: string | URL | Request, init?: RequestInit) =>
			handler(input instanceof Request ? input : new Request(input, init)),
		{ preconnect: fetch.preconnect },
	);
	const provider = new HttpProvider(origin, partnerToken, transport);
	const client = new IdentityClient(join(directory, "client.pem"));
	const admission = new Admission({
		merchantId: "shop",
		origin: merchantOrigin,
		enrollmentUrl: `${origin}/v0/enroll`,
		provider,
		journal,
	});
	return {
		directory,
		store,
		journal,
		handler,
		transport,
		provider,
		client,
		admission,
	};
}
test("deterministic policy denies before execution and attributes only verified proof", async () => {
	const { client, handler, provider, journal } = setup();
	const identity = await client.enroll(`${origin}/v0/enroll`, handler);
	const admission = new Admission({
		merchantId: "shop",
		origin: merchantOrigin,
		enrollmentUrl: `${origin}/v0/enroll`,
		provider,
		journal,
		evaluate: (evidence) => {
			expect(evidence.history).toBe("insufficient");
			return null;
		},
	});
	let calls = 0;
	expect(
		(
			await admission.run(
				client.request(`${merchantOrigin}/sessions`, {}),
				async () => {
					calls++;
					return Response.json({});
				},
			)
		).status,
	).toBe(403);
	const valid = client.request(`${merchantOrigin}/sessions`, {});
	expect(
		(
			await admission.run(
				new Request(valid.url, {
					method: "POST",
					headers: valid.headers,
					body: '{"tampered":true}',
				}),
				async () => {
					calls++;
					return Response.json({});
				},
			)
		).status,
	).toBe(401);
	await admission.flush();
	const history = await provider.history(identity.identityId);
	expect(calls).toBe(0);
	expect(history).toHaveLength(1);
	expect(history[0]).toMatchObject({ outcome: "denied", reason: "policy" });
});
test("evaluation may restrict but cannot extend configured permissions", async () => {
	const { client, handler, provider, journal } = setup();
	await client.enroll(`${origin}/v0/enroll`, handler);
	const admission = new Admission({
		merchantId: "shop",
		origin: merchantOrigin,
		enrollmentUrl: `${origin}/v0/enroll`,
		provider,
		journal,
		evaluate: () => ["searchProducts", "completeCheckout"],
	});
	expect(
		(
			await admission.run(
				client.request(`${merchantOrigin}/sessions`, {}),
				async () => {
					expect(admission.allows("searchProducts")).toBe(true);
					expect(admission.allows("createCart")).toBe(false);
					expect(admission.allows("completeCheckout")).toBe(false);
					return Response.json({});
				},
			)
		).status,
	).toBe(200);
});
test("missing extension activation uses binding-specific A2A errors before runtime", async () => {
	const { client, handler, admission } = setup();
	await client.enroll(`${origin}/v0/enroll`, handler);
	const next = async () => {
		throw new Error("MUST NOT RUN");
	};
	const rpc = await admission.run(
		client.request(`${merchantOrigin}/`, {
			jsonrpc: "2.0",
			id: "rpc-1",
			method: "message/send",
			params: {},
		}),
		next,
	);
	expect(rpc.status).toBe(400);
	expect(await rpc.json()).toMatchObject({
		jsonrpc: "2.0",
		id: "rpc-1",
		error: { code: -32008 },
	});
	const http = await admission.run(
		client.request(`${merchantOrigin}/message:send`, {}),
		next,
	);
	expect(http.status).toBe(400);
	expect(http.headers.get("content-type")).toBe("application/problem+json");
	expect(await http.json()).toHaveProperty(
		"type",
		"https://a2a-protocol.org/errors/extension-support-required",
	);
});
test("replay claims survive a closed journal and expire only after freshness ends", () => {
	const { directory } = setup();
	const path = join(directory, "replay.sqlite");
	const first = new SqliteJournal(path);
	first.claim("shop:key", "unique-nonce", 100, 0);
	first.close();
	const second = new SqliteJournal(path);
	cleanups.push(() => second.close());
	expect(() => second.claim("shop:key", "unique-nonce", 100, 0)).toThrow(
		"replay",
	);
	second.claim("other:key", "unique-nonce", 100, 0);
	second.claim("shop:key", "unique-nonce", 200, 101);
});
test("aggregate evidence is not truncated to the history page and never crosses tenant", async () => {
	const { client, handler, store } = setup();
	const identity = await client.enroll(`${origin}/v0/enroll`, handler);
	const events: AuditEvent[] = Array.from({ length: 1001 }, () => ({
		eventId: randomUUID(),
		requestId: randomUUID(),
		identityId: identity.identityId,
		type: "interaction",
		operation: "request",
		outcome: "success",
		reason: "completed",
		occurredAt: new Date().toISOString(),
		ruleVersion: RULE_VERSION,
	}));
	await store.ingest("shop", events);
	expect(
		(await store.resolve(identity.thumbprint!, "shop"))?.interactions,
	).toBe(1001);
	expect(
		(await store.resolve(identity.thumbprint!, "other"))?.interactions,
	).toBe(0);
	expect(await store.events("shop", identity.identityId)).toHaveLength(1000);
});
test("concurrent copies of one signed request execute business logic only once", async () => {
	const { client, handler, admission } = setup();
	await client.enroll(`${origin}/v0/enroll`, handler);
	const request = client.request(`${merchantOrigin}/sessions`, {});
	let calls = 0;
	const next = async () => {
		calls++;
		await Bun.sleep(10);
		return Response.json({});
	};
	const responses = await Promise.all([
		admission.run(request.clone(), next),
		admission.run(request.clone(), next),
	]);
	expect(responses.map((r) => r.status).sort()).toEqual([200, 409]);
	expect(calls).toBe(1);
});
test("challenge before business logic and public discovery remains available", async () => {
	const { admission } = setup();
	let calls = 0;
	const next = async () => {
		calls++;
		return Response.json({ ok: true });
	};
	const challenge = await admission.run(
		new Request(`${merchantOrigin}/sessions`, { method: "POST", body: "{}" }),
		next,
	);
	expect(challenge.status).toBe(401);
	expect(calls).toBe(0);
	expect(challenge.headers.get("www-authenticate")).toContain("AgentSignature");
	expect(await challenge.json()).toHaveProperty(
		"enrollment.url",
		`${origin}/v0/enroll`,
	);
	expect(
		(
			await admission.run(
				new Request(`${merchantOrigin}/.well-known/agent-card.json`),
				next,
			)
		).status,
	).toBe(200);
});
test("enrollment and identity persist across client and provider restart", async () => {
	const { client, handler, directory, store } = setup();
	const first = await client.enroll(`${origin}/v0/enroll`, handler);
	const restarted = new IdentityClient(join(directory, "client.pem"));
	expect(
		(await restarted.enroll(`${origin}/v0/enroll`, handler)).identityId,
	).toBe(first.identityId);
	const secondStore = new SqliteIdentityStore(
		join(directory, "provider.sqlite"),
	);
	cleanups.push(() => secondStore.close());
	expect(
		(await secondStore.resolve(first.thumbprint!, "shop"))?.identity.identityId,
	).toBe(first.identityId);
	await store.revoke(first.identityId);
	expect(
		(
			await handler(
				client.request(`${origin}/v0/enroll`, { publicKey: client.publicKey }),
			)
		).status,
	).toBe(401);
});
test("signed bytes forwarded, repeated nonce blocked and revocation rechecked", async () => {
	const { client, handler, store, admission, provider } = setup();
	const identity = await client.enroll(`${origin}/v0/enroll`, handler);
	let calls = 0;
	const request = client.request(`${merchantOrigin}/sessions`, {
		channel: "a2a",
	});
	const retry = request.clone();
	const response = await admission.run(request, async (body) => {
		calls++;
		expect(await body.text()).toBe('{"channel":"a2a"}');
		expect(admission.current()?.identityId).toBe(identity.identityId);
		return Response.json({ ok: true });
	});
	expect(response.status).toBe(200);
	expect(
		(
			await admission.run(retry, async () => {
				calls++;
				return Response.json({});
			})
		).status,
	).toBe(409);
	expect(calls).toBe(1);
	expect(admission.current()).toBeUndefined();
	await admission.flush();
	const history = await provider.history(identity.identityId);
	expect(
		history.some((e) => e.type === "interaction" && e.outcome === "success"),
	).toBe(true);
	await store.revoke(identity.identityId);
	expect(
		(
			await admission.run(
				client.request(`${merchantOrigin}/sessions`, {}),
				async () => {
					calls++;
					return Response.json({});
				},
			)
		).status,
	).toBe(401);
	expect(calls).toBe(1);
});
test("tampered body, URL, stale proof, unknown key all refuse execution", async () => {
	const { client, handler, admission, directory } = setup();
	await client.enroll(`${origin}/v0/enroll`, handler);
	const valid = client.request(`${merchantOrigin}/sessions`, {});
	const cases = [
		new Request(valid.url, {
			method: "POST",
			headers: valid.headers,
			body: '{"changed":true}',
		}),
		new Request(`${merchantOrigin}/chat`, {
			method: "POST",
			headers: valid.headers,
			body: "{}",
		}),
		client.request(valid.url, {}, { created: 1 }),
		new IdentityClient(join(directory, "unknown.pem")).request(valid.url, {}),
	];
	for (const request of cases)
		expect(
			(
				await admission.run(request, async () => {
					throw new Error("MUST NOT RUN");
				})
			).status,
		).toBe(401);
});
test("provisional is observation only and invalid authentication never downgrades", async () => {
	const { client, provider, journal } = setup();
	const admission = new Admission({
		merchantId: "shop",
		origin: merchantOrigin,
		enrollmentUrl: `${origin}/v0/enroll`,
		provider,
		journal,
		mode: "restricted",
	});
	let first: string | undefined;
	const run = async () => {
		expect(admission.allows("createCart")).toBe(false);
		expect(admission.allows("searchProducts")).toBe(true);
		expect(admission.canResume("old-session")).toBe(false);
		const id = admission.current()?.identityId;
		expect(id).not.toBe(first);
		first = id;
		return Response.json({});
	};
	for (let i = 0; i < 2; i++)
		expect(
			(
				await admission.run(
					new Request(`${merchantOrigin}/sessions`, {
						method: "POST",
						body: "{}",
					}),
					run,
				)
			).status,
		).toBe(200);
	expect(
		(await admission.run(client.request(`${merchantOrigin}/sessions`, {}), run))
			.status,
	).toBe(401);
});
test("provider outage prevents runtime; outbox resumes delivery and deduplicates", async () => {
	const { client, handler, admission, provider, store, directory } = setup();
	const identity = await client.enroll(`${origin}/v0/enroll`, handler);
	await admission.run(
		client.request(`${merchantOrigin}/sessions`, {}),
		async () => Response.json({}),
	);
	const restarted = new SqliteJournal(join(directory, "outbox.sqlite"));
	cleanups.push(() => restarted.close());
	const down: Provider = {
		resolve: async () => {
			throw new Error("offline");
		},
		provisional: async () => {
			throw new Error("offline");
		},
		ingest: async () => {
			throw new Error("offline");
		},
	};
	await expect(restarted.flush(down)).rejects.toThrow("offline");
	expect(await restarted.flush(provider)).toBe(2);
	expect(await restarted.flush(provider)).toBe(0);
	const events = await provider.history(identity.identityId);
	await store.ingest("shop", events);
	expect(await provider.history(identity.identityId)).toHaveLength(2);
	expect(await store.events("other", identity.identityId)).toEqual([]);
	const denied = new Admission({
		merchantId: "shop",
		origin: merchantOrigin,
		enrollmentUrl: `${origin}/v0/enroll`,
		provider: down,
		journal: restarted,
	});
	expect(
		(
			await denied.run(
				client.request(`${merchantOrigin}/sessions`, {}),
				async () => {
					throw new Error("MUST NOT RUN");
				},
			)
		).status,
	).toBe(503);
});
test("full audit journal refuses before effect; incomplete result recovers as unknown", async () => {
	const { directory, client, handler, provider } = setup();
	const identity = await client.enroll(`${origin}/v0/enroll`, handler);
	const path = join(directory, "small.sqlite");
	const journal = new SqliteJournal(path, 2);
	const event: AuditEvent = {
		eventId: randomUUID(),
		requestId: randomUUID(),
		identityId: identity.identityId,
		type: "interaction",
		operation: "request",
		outcome: "unknown",
		reason: "unavailable",
		ruleVersion: RULE_VERSION,
		occurredAt: new Date().toISOString(),
	};
	journal.append(event, false);
	journal.close();
	const restarted = new SqliteJournal(path, 2);
	cleanups.push(() => restarted.close());
	const admission = new Admission({
		merchantId: "shop",
		origin: merchantOrigin,
		enrollmentUrl: `${origin}/v0/enroll`,
		provider,
		journal: restarted,
	});
	let calls = 0;
	expect(
		(
			await admission.run(
				client.request(`${merchantOrigin}/sessions`, {}),
				async () => {
					calls++;
					return Response.json({});
				},
			)
		).status,
	).toBe(503);
	expect(calls).toBe(0);
	await restarted.flush(provider);
	expect(
		(await provider.history(identity.identityId)).find(
			(e) => e.eventId === event.eventId,
		)?.outcome,
	).toBe("unknown");
});
test("private endpoints require distinct credentials and reject extra event payload", async () => {
	const { handler, client } = setup();
	for (const path of [
		"/v0/resolve",
		"/v0/provisional",
		"/v0/events",
		"/v0/history",
		"/v0/admin/revoke",
	]) {
		expect(
			(
				await handler(
					new Request(`${origin}${path}`, { method: "POST", body: "{}" }),
				)
			).status,
		).toBe(401);
	}
	expect(
		(
			await handler(
				client.request(`${origin}/v0/enroll`, {
					publicKey: { ...client.publicKey, d: "PRIVATE" },
				}),
			)
		).status,
	).toBe(400);
});
