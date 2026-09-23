import { mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join, resolve } from "node:path";
import { z } from "zod";
import { Admission } from "../src/admission.js";
import { IdentityClient } from "../src/client.js";
import { createProviderHandler, HttpProvider } from "../src/provider.js";
import { SqliteIdentityStore, SqliteJournal } from "../src/sqlite.js";
import { makeHarness } from "./harness-fixture.js";

const directory = resolve(".local/demo");
mkdirSync(directory, { recursive: true, mode: 0o700 });
const store = new SqliteIdentityStore(join(directory, "provider.sqlite"));
const journal = new SqliteJournal(join(directory, "outbox.sqlite"));
const localToken = "local-demo-only-partner-token-not-for-deployment";
let providerHandle = async (_: Request) => new Response(null, { status: 503 });
let sellerHandle = providerHandle;
const providerServer = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	fetch: (request) => providerHandle(request),
});
const sellerServer = Bun.serve({
	hostname: "127.0.0.1",
	port: 0,
	fetch: (request) => sellerHandle(request),
});
const providerOrigin = `http://127.0.0.1:${providerServer.port}`,
	sellerOrigin = `http://127.0.0.1:${sellerServer.port}`;
providerHandle = createProviderHandler({
	origin: providerOrigin,
	store,
	partners: [{ merchantId: "shop", token: localToken }],
	adminToken: "local-demo-only-admin-token-not-for-deployment",
	allowLoopback: true,
});
const provider = new HttpProvider(providerOrigin, localToken, fetch, true);
const admission = new Admission({
	merchantId: "shop",
	origin: sellerOrigin,
	enrollmentUrl: `${providerOrigin}/v0/enroll`,
	provider,
	journal,
	allowLoopback: true,
});
const harness = makeHarness(admission, join(directory, "sessions.sqlite"));
sellerHandle = (request) => harness.handler.handle(request);
const client = new IdentityClient(join(directory, "client.pem"), true);
function message(contextId?: string) {
	return {
		message: {
			messageId: randomUUID(),
			role: "user",
			parts: [{ kind: "text", text: "Find a synthetic jacket" }],
			...(contextId ? { contextId } : {}),
		},
	};
}
async function requireStatus(
	response: Response,
	status: number,
): Promise<Response> {
	if (response.status !== status)
		throw new Error(`Expected ${status}, received ${response.status}`);
	return response;
}
try {
	await requireStatus(
		await fetch(`${sellerOrigin}/.well-known/agent-card.json`),
		200,
	);
	console.log("1. Public Agent Card discovered.");
	await requireStatus(
		await fetch(`${sellerOrigin}/message:send`, {
			method: "POST",
			body: JSON.stringify(message()),
		}),
		401,
	);
	if (harness.calls.runtime !== 0)
		throw new Error("Challenge did not precede runtime");
	console.log("2. Unsigned request challenged before any runtime call.");
	const identity = await client.enroll(`${providerOrigin}/v0/enroll`);
	console.log(
		`3. Enrolled ${identity.identityId}; private key kept only in ${join(directory, "client.pem")}.`,
	);
	const request = client.request(`${sellerOrigin}/message:send`, message(), {
		a2a: true,
	});
	const replay = request.clone();
	const task = z
		.object({ id: z.string(), contextId: z.string() })
		.parse(await (await requireStatus(await fetch(request), 200)).json());
	console.log(`4. A2A task ${task.id}; session ${task.contextId}.`);
	await requireStatus(await fetch(replay), 409);
	console.log("5. Replayed signed request rejected.");
	const restartedClient = new IdentityClient(
		join(directory, "client.pem"),
		true,
	);
	const again = await restartedClient.enroll(`${providerOrigin}/v0/enroll`);
	if (again.identityId !== identity.identityId)
		throw new Error("Identity changed after key reload");
	await requireStatus(
		await fetch(
			restartedClient.request(
				`${sellerOrigin}/message:send`,
				message(task.contextId),
				{ a2a: true },
			),
		),
		200,
	);
	console.log("6. Reloaded key: same identity and authorized session resumed.");
	await admission.flush();
	const history = await provider.history(identity.identityId);
	console.log(
		`7. ${history.length} minimal audit events persisted; no prompts, responses or private keys exported.`,
	);
	console.log(
		"Run this command again: provider and client restart, identity remains unchanged.",
	);
} finally {
	await providerServer.stop(true);
	await sellerServer.stop(true);
	journal.close();
	store.close();
}
