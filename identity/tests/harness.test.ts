import { afterEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { makeHarness } from "../examples/harness-fixture.js";
import { Admission } from "../src/admission.js";
import { IdentityClient } from "../src/client.js";
import { createProviderHandler } from "../src/provider.js";
import { SqliteIdentityStore, SqliteJournal } from "../src/sqlite.js";
import type { Provider } from "../src/contracts.js";

const pending: (() => void)[] = [];
afterEach(() => {
	for (const done of pending.splice(0).reverse()) done();
});
function setup(mode: "challenge" | "restricted" = "challenge") {
	const dir = mkdtempSync(join(tmpdir(), "aithos-harness-test-"));
	pending.push(() => rmSync(dir, { recursive: true }));
	const store = new SqliteIdentityStore(join(dir, "identities.sqlite")),
		journal = new SqliteJournal(join(dir, "journal.sqlite"));
	pending.push(
		() => store.close(),
		() => journal.close(),
	);
	const provider: Provider = {
		resolve: (t) => store.resolve(t, "shop"),
		provisional: () => store.provisional("shop"),
		ingest: (e) => store.ingest("shop", e),
	};
	const providerHandler = createProviderHandler({
		origin: "https://identity.test",
		store,
		partners: [],
		adminToken: "admin-token-test-".repeat(3),
	});
	const admission = new Admission({
		merchantId: "shop",
		origin: "https://seller.test",
		enrollmentUrl: "https://identity.test/v0/enroll",
		provider,
		journal,
		mode,
	});
	const harness = makeHarness(admission, join(dir, "sessions.sqlite"));
	const alice = new IdentityClient(join(dir, "alice.pem")),
		bob = new IdentityClient(join(dir, "bob.pem"));
	const signed = (client: IdentityClient, path: string, body: unknown) =>
		harness.handler.handle(
			client.request(`https://seller.test${path}`, body, {
				a2a: path === "/" || path === "/message:send",
			}),
		);
	const enroll = (client: IdentityClient) =>
		client.enroll("https://identity.test/v0/enroll", providerHandler);
	return {
		dir,
		store,
		journal,
		provider,
		admission,
		harness,
		alice,
		bob,
		signed,
		enroll,
	};
}
const sessionSchema = z.object({ agentSessionId: z.string() });
const taskSchema = z.object({ contextId: z.string(), id: z.string() });
function message(session?: string, text = "catalogue", metadata?: object) {
	return {
		message: {
			messageId: randomUUID(),
			role: "user",
			parts: [{ kind: "text", text }],
			...(session ? { contextId: session } : {}),
			...(metadata ? { metadata } : {}),
		},
	};
}
test("all protected transports challenge before runtime, session or commerce", async () => {
	const { harness } = setup();
	for (const path of [
		"/",
		"/message:send",
		"/chat",
		"/sessions",
		"/commerce/a2a",
		"/commerce/customer",
	]) {
		expect(
			(
				await harness.handler.handle(
					new Request(`https://seller.test${path}`, {
						method: "POST",
						body: "{}",
					}),
				)
			).status,
		).toBe(401);
	}
	expect(harness.calls).toEqual({
		runtime: 0,
		catalog: 0,
		cart: 0,
		payment: 0,
	});
	const card = await harness.handler.handle(
		new Request("https://seller.test/.well-known/agent-card.json"),
	);
	expect(await card.json()).toHaveProperty("capabilities.extensions");
});
test("A2A discovery → enrollment → task → same identity after restart", async () => {
	const { alice, enroll, signed, dir, admission, store, harness } = setup();
	const identity = await enroll(alice);
	const first = await signed(alice, "/message:send", message());
	expect(first.status).toBe(200);
	const task = taskSchema.parse(await first.json());
	expect(
		harness.store.getSession(task.contextId, "shop")?.callerIdentityId,
	).toBe(identity.identityId);
	const restartedClient = new IdentityClient(join(dir, "alice.pem"));
	const restartedHarness = makeHarness(admission, join(dir, "sessions.sqlite"));
	const second = await restartedHarness.handler.handle(
		restartedClient.request(
			"https://seller.test/message:send",
			message(task.contextId),
			{ a2a: true },
		),
	);
	expect(second.status).toBe(200);
	expect(second.headers.get("aithos-identity-id")).toBe(identity.identityId);
	await admission.flush();
	const events = await store.events("shop", identity.identityId);
	expect(events.some((e) => e.operation === "searchProducts")).toBe(true);
	expect(JSON.stringify(events)).not.toContain("Synthetic");
	expect(JSON.stringify(events)).not.toContain("shopwareContextToken");
});
test("Bob cannot resume Alice via chat, REST, JSONRPC, commerce or mandate injection", async () => {
	const { alice, bob, enroll, signed, harness } = setup();
	await enroll(alice);
	await enroll(bob);
	const created = await signed(alice, "/sessions", { channel: "a2a" });
	const id = sessionSchema.parse(await created.json()).agentSessionId;
	const cases: [string, unknown][] = [
		["/chat", { agentSessionId: id, message: "catalogue" }],
		["/message:send", message(id)],
		[
			"/",
			{
				jsonrpc: "2.0",
				id: 1,
				method: "message/send",
				params: message(id, "catalogue", {
					supportedPaymentHandlers: ["forged"],
				}),
			},
		],
		[
			"/commerce/a2a",
			{ agentSessionId: id, capability: "searchProducts", query: "x" },
		],
		[
			"/commerce/customer",
			{
				agentSessionId: id,
				capability: "createCart",
				items: [{ productId: "x", quantity: 1 }],
			},
		],
	];
	for (const [path, body] of cases)
		expect((await signed(bob, path, body)).status).toBe(403);
	expect(harness.calls.runtime).toBe(0);
	expect(harness.calls.catalog).toBe(0);
	expect(harness.calls.cart).toBe(0);
});
test("conflicting identifiers and externally supplied Shopware context are rejected", async () => {
	const { alice, enroll, signed, harness } = setup();
	await enroll(alice);
	expect(
		(
			await signed(
				alice,
				"/message:send",
				message("one", "x", { agentSessionId: "two" }),
			)
		).status,
	).toBe(400);
	expect(
		(
			await signed(alice, "/sessions", {
				channel: "a2a",
				shopwareContextToken: "forged-secret",
			})
		).status,
	).toBe(403);
	expect(
		(await signed(alice, "/sessions", { channel: "internal_demo" })).status,
	).toBe(403);
	expect(
		(
			await signed(alice, "/sessions", {
				channel: "a2a",
				customerContext: { customerGroup: "vip" },
			})
		).status,
	).toBe(403);
	expect(harness.calls.runtime).toBe(0);
});
test("provisional can browse once, not resume or bypass policy through model tools", async () => {
	const { harness, admission } = setup("restricted");
	const send = (body: unknown) =>
		harness.handler.handle(
			new Request("https://seller.test/message:send", {
				method: "POST",
				headers: { "content-type": "application/json", "a2a-version": "1.0.0" },
				body: JSON.stringify(body),
			}),
		);
	const response = await send(message());
	expect(response.status).toBe(200);
	const task = taskSchema.parse(await response.json());
	expect((await send(message(task.contextId))).status).toBe(403);
	expect((await send(message(undefined, "attempt-cart"))).status).toBe(403);
	expect(harness.calls.cart).toBe(0);
	expect(harness.calls.payment).toBe(0);
	await admission.flush();
});
test("concurrent identities remain isolated and legacy sessions cannot be claimed", async () => {
	const { alice, bob, enroll, signed, harness } = setup();
	const [a, b] = await Promise.all([enroll(alice), enroll(bob)]);
	const responses = await Promise.all([
		signed(alice, "/message:send", message()),
		signed(bob, "/message:send", message()),
	]);
	for (const [index, response] of responses.entries()) {
		const task = taskSchema.parse(await response.json());
		expect(
			harness.store.getSession(task.contextId, "shop")?.callerIdentityId,
		).toBe(index === 0 ? a.identityId : b.identityId);
	}
	harness.store.createSession({
		agentSessionId: "legacy",
		merchantId: "shop",
		agentId: "seller",
		channel: "a2a",
		customerContext: {},
		createdAt: new Date(),
	});
	expect(
		(
			await signed(alice, "/commerce/a2a", {
				capability: "searchProducts",
				query: "x",
				agentSessionId: "legacy",
			})
		).status,
	).toBe(403);
	expect(
		harness.store.getSession("legacy", "shop")?.callerIdentityId,
	).toBeUndefined();
});
test("implicit creation binds once; caller cannot overwrite an expired or other-merchant session", async () => {
	const { alice, bob, enroll, signed, harness } = setup();
	const a = await enroll(alice);
	await enroll(bob);
	const body = {
		capability: "searchProducts",
		query: "x",
		agentSessionId: "client-chosen",
	};
	expect((await signed(alice, "/commerce/a2a", body)).status).toBe(200);
	expect(
		harness.store.getSession("client-chosen", "shop")?.callerIdentityId,
	).toBe(a.identityId);
	expect((await signed(bob, "/commerce/a2a", body)).status).toBe(403);
	harness.store.createSession({
		agentSessionId: "expired",
		merchantId: "shop",
		agentId: "seller",
		callerIdentityId: a.identityId,
		channel: "a2a",
		customerContext: {},
		createdAt: new Date(0),
		expiresAt: new Date(1),
	});
	expect(
		(await signed(bob, "/commerce/a2a", { ...body, agentSessionId: "expired" }))
			.status,
	).not.toBe(200);
});
