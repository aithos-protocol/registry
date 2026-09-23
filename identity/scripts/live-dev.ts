import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { Admission } from "../src/admission.js";
import { IdentityClient } from "../src/client.js";
import { HttpProvider } from "../src/provider.js";
import { SqliteJournal } from "../src/sqlite.js";
import { thumbprint } from "../src/signatures.js";
import { makeHarness } from "../examples/harness-fixture.js";

// Synthetic records only. No real Shopware endpoint, model, order or payment.
const config = z
	.object({
		origin: z.url(),
		partners: z.array(z.object({ merchantId: z.string(), token: z.string() })),
		adminToken: z.string(),
	})
	.parse(JSON.parse(readFileSync(".local/dev-access.json", "utf8")));
if (config.origin !== "https://8zbvp0lv2a.execute-api.us-east-1.amazonaws.com")
	throw new Error("Refusing an unrecognized deployment");
const shop = config.partners.find((p) => p.merchantId === "shop");
const other = config.partners.find((p) => p.merchantId === "other");
if (!shop || !other)
	throw new Error("Both synthetic tenants must be configured");
let lastRequest = 0;
const paced: typeof fetch = Object.assign(
	async (...args: Parameters<typeof fetch>) => {
		await Bun.sleep(Math.max(0, 850 - (Date.now() - lastRequest)));
		lastRequest = Date.now();
		return fetch(...args);
	},
	{ preconnect: fetch.preconnect },
);
const provider = new HttpProvider(config.origin, shop.token, paced);
const otherProvider = new HttpProvider(config.origin, other.token, paced);
const directory = join(".local/live", randomUUID());
mkdirSync(directory, { recursive: true, mode: 0o700 });
const journal = new SqliteJournal(join(directory, "outbox.sqlite"));
const admission = new Admission({
	merchantId: "shop",
	origin: "https://seller.test",
	enrollmentUrl: `${config.origin}/v0/enroll`,
	provider,
	journal,
});
const harness = makeHarness(admission, join(directory, "sessions.sqlite"));
const clientPath = join(directory, "client.pem");
const client = new IdentityClient(clientPath);
const message = (contextId?: string) => ({
	message: {
		messageId: randomUUID(),
		role: "user",
		parts: [{ kind: "text", text: "Synthetic catalogue query" }],
		...(contextId ? { contextId } : {}),
	},
});
function check(condition: unknown, label: string): asserts condition {
	if (!condition) throw new Error(`Check failed: ${label}`);
	console.log(`PASS ${label}`);
}
async function post(
	path: string,
	body: unknown,
	token: string,
): Promise<Response> {
	return paced(`${config.origin}${path}`, {
		method: "POST",
		headers: {
			authorization: `Bearer ${token}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
		redirect: "error",
		signal: AbortSignal.timeout(10000),
	});
}
let enrolled: string | undefined;
let revoked = false;
try {
	check(
		(await paced(`${config.origin}/health`)).status === 200,
		"hosted health",
	);
	const unsigned = await harness.handler.handle(
		new Request("https://seller.test/message:send", {
			method: "POST",
			body: JSON.stringify(message()),
		}),
	);
	check(
		unsigned.status === 401 && harness.calls.runtime === 0,
		"unsigned caller stopped before runtime",
	);
	const identity = await client.enroll(`${config.origin}/v0/enroll`, paced);
	enrolled = identity.identityId;
	const restarted = new IdentityClient(clientPath);
	const again = await restarted.enroll(`${config.origin}/v0/enroll`, paced);
	check(
		identity.identityId === again.identityId,
		"DynamoDB identity reused after client restart",
	);
	const first = client.request("https://seller.test/message:send", message(), {
		a2a: true,
	});
	const replay = first.clone();
	const response = await harness.handler.handle(first);
	check(
		response.status === 200,
		"real harness admitted using hosted identity resolution",
	);
	const task = z.object({ contextId: z.string() }).parse(await response.json());
	check(
		(await harness.handler.handle(replay)).status === 409,
		"signed replay refused",
	);
	check(
		(
			await harness.handler.handle(
				restarted.request(
					"https://seller.test/message:send",
					message(task.contextId),
					{ a2a: true },
				),
			)
		).status === 200,
		"owned session resumed",
	);
	await admission.flush();
	const history = await provider.history(identity.identityId);
	const evaluation = await provider.resolve(thumbprint(client.publicKey));
	check(
		history.length >= 7 && evaluation?.interactions === 2,
		"private audit and evidence persisted",
	);
	await provider.ingest(history);
	check(
		(await provider.resolve(thumbprint(client.publicKey)))?.interactions === 2,
		"audit retry does not double count",
	);
	check(
		(await otherProvider.history(identity.identityId)).length === 0 &&
			(await otherProvider.resolve(thumbprint(client.publicKey)))
				?.interactions === 0,
		"tenant history isolation",
	);
	const ephemeral = await otherProvider.provisional();
	const sample = history[0];
	if (!sample) throw new Error("Missing event");
	check(
		(
			await post(
				"/v0/events",
				{
					events: [
						{
							...sample,
							eventId: randomUUID(),
							identityId: ephemeral.identityId,
						},
					],
				},
				shop.token,
			)
		).status === 403,
		"provisional tenant scope enforced",
	);
	check(
		(
			await post(
				"/v0/admin/revoke",
				{ identityId: identity.identityId },
				shop.token,
			)
		).status === 401,
		"partner credential cannot revoke globally",
	);
	check(
		(
			await post(
				"/v0/admin/revoke",
				{ identityId: identity.identityId },
				config.adminToken,
			)
		).status === 200,
		"administrator revocation",
	);
	revoked = true;
	const callsBefore = harness.calls.runtime;
	check(
		(
			await harness.handler.handle(
				client.request("https://seller.test/message:send", message(), {
					a2a: true,
				}),
			)
		).status === 401 && harness.calls.runtime === callsBefore,
		"revoked identity stopped before runtime",
	);
	check(
		(
			await paced(
				client.request(`${config.origin}/v0/enroll`, {
					publicKey: client.publicKey,
				}),
			)
		).status === 401,
		"re-enrollment cannot reactivate revoked key",
	);
	await admission.flush();
	console.log(
		JSON.stringify({
			origin: config.origin,
			identityId: identity.identityId,
			synthetic: true,
			revoked: true,
			keyDirectory: directory,
		}),
	);
} finally {
	if (enrolled && !revoked) {
		const result = await post(
			"/v0/admin/revoke",
			{ identityId: enrolled },
			config.adminToken,
		);
		if (!result.ok)
			console.error("Synthetic identity revocation needs operator attention");
	}
	journal.close();
}
