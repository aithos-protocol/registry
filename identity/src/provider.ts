import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import {
	enrollmentSchema,
	evaluationSchema,
	eventBatchSchema,
	identitySchema,
	eventSchema,
	idSchema,
	thumbSchema,
	IdentityError,
	fail,
	problem,
	type AuditEvent,
	type IdentityStore,
	type Provider,
} from "./contracts.js";
import { digest, parseProof, thumbprint, verifyProof } from "./signatures.js";
import { boundedBody, RateLimiter, trustedUrl } from "./http.js";

export interface ProviderConfig {
	origin: string;
	store: IdentityStore;
	partners: readonly { merchantId: string; token: string }[];
	adminToken: string;
	allowLoopback?: boolean;
	now?: () => number;
	retentionDays?: number;
}
export function createProviderHandler(
	config: ProviderConfig,
): (request: Request) => Promise<Response> {
	if (
		config.adminToken.length < 32 ||
		config.partners.some(
			(p) =>
				p.token.length < 32 ||
				p.token === config.adminToken ||
				!idSchema.safeParse(p.merchantId).success,
		) ||
		new Set(config.partners.map((p) => p.token)).size !== config.partners.length
	)
		throw new Error("Use separate strong partner/admin credentials");
	const enrollmentLimit = new RateLimiter(60),
		privateLimit = new RateLimiter(600);
	trustedUrl(
		new Request(`${config.origin}/`),
		config.origin,
		config.allowLoopback,
	);
	return async (request) => {
		try {
			const url = new URL(
				trustedUrl(request, config.origin, config.allowLoopback),
			);
			if (request.method === "GET" && url.pathname === "/health")
				return Response.json({ status: "ok" });
			if (request.method !== "POST" || url.search) fail(404, "not_found");
			if (url.pathname === "/v0/enroll") {
				enrollmentLimit.check("global"); // Bounded across all self-asserted keys; edge adds per-IP throttling.
				const body = await boundedBody(request, 8192);
				const input = enrollmentSchema.parse(
					JSON.parse(Buffer.from(body).toString()),
				);
				const thumb = thumbprint(input.publicKey);
				const proof = parseProof(
					request.method,
					url.href,
					[...request.headers],
					[],
					config.allowLoopback,
				);
				if (proof.keyId !== `aithos-client:${thumb}`)
					fail(401, "invalid_proof");
				verifyProof(proof, input.publicKey, body, config.now?.());
				return Response.json(
					await config.store.enroll(input.publicKey, thumb),
					{ headers: { "cache-control": "no-store" } },
				);
			}
			const credential = request.headers.get("authorization") ?? "";
			if (url.pathname === "/v0/admin/revoke") {
				if (!equal(credential, `Bearer ${config.adminToken}`))
					fail(401, "invalid_credentials");
				const input = z
					.strictObject({ identityId: idSchema })
					.parse(await read(request));
				await config.store.revoke(input.identityId);
				return Response.json({ revoked: true });
			}
			const partner = config.partners.find((p) =>
				equal(credential, `Bearer ${p.token}`),
			);
			if (!partner) fail(401, "invalid_credentials");
			privateLimit.check(partner.merchantId);
			const input = await read(request);
			switch (url.pathname) {
				case "/v0/resolve": {
					const data = z.strictObject({ thumbprint: thumbSchema }).parse(input);
					return Response.json(
						await config.store.resolve(data.thumbprint, partner.merchantId),
						{ headers: { "cache-control": "no-store" } },
					);
				}
				case "/v0/provisional":
					z.strictObject({}).parse(input);
					return Response.json(
						await config.store.provisional(partner.merchantId),
					);
				case "/v0/events": {
					const { events } = eventBatchSchema.parse(input);
					const now = config.now?.() ?? Date.now();
					if (
						events.some(
							(e) =>
								Date.parse(e.occurredAt) > now + 60000 ||
								Date.parse(e.occurredAt) <
									now - (config.retentionDays ?? 7) * 86400000,
						)
					)
						fail(422, "event_outside_retention");
					await config.store.ingest(partner.merchantId, events);
					return Response.json({ accepted: events.length });
				}
				case "/v0/history": {
					const { identityId } = z
						.strictObject({ identityId: idSchema })
						.parse(input);
					return Response.json({
						events: await config.store.events(partner.merchantId, identityId),
					});
				}
				default:
					return fail(404, "not_found");
			}
		} catch (error) {
			if (error instanceof z.ZodError || error instanceof SyntaxError)
				return problem(new IdentityError(400, "invalid_input"));
			return problem(error);
		}
	};
}
const equal = (a: string, b: string) => timingSafeEqual(digest(a), digest(b));
async function read(request: Request): Promise<unknown> {
	return JSON.parse(Buffer.from(await boundedBody(request, 131072)).toString());
}

export class HttpProvider implements Provider {
	constructor(
		readonly origin: string,
		private readonly token: string,
		private readonly transport: typeof fetch = fetch,
		readonly allowLoopback = false,
	) {
		trustedUrl(new Request(`${origin}/`), origin, allowLoopback);
	}
	private async post(path: string, body: unknown): Promise<unknown> {
		const response = await this.transport(`${this.origin}${path}`, {
			method: "POST",
			headers: {
				authorization: `Bearer ${this.token}`,
				"content-type": "application/json",
			},
			body: JSON.stringify(body),
			signal: AbortSignal.timeout(5000),
			redirect: "error",
		});
		if (!response.ok) fail(503, "provider_unavailable");
		return JSON.parse(
			Buffer.from(await boundedBody(response, 1024 * 1024)).toString(),
		);
	}
	async resolve(thumbprint: string) {
		return evaluationSchema
			.nullable()
			.parse(await this.post("/v0/resolve", { thumbprint }));
	}
	async provisional() {
		return identitySchema.parse(await this.post("/v0/provisional", {}));
	}
	async ingest(events: AuditEvent[]): Promise<void> {
		z.strictObject({ accepted: z.literal(events.length) }).parse(
			await this.post("/v0/events", { events }),
		);
	}
	async history(identityId: string): Promise<AuditEvent[]> {
		return z
			.strictObject({ events: z.array(eventSchema) })
			.parse(await this.post("/v0/history", { identityId })).events;
	}
}
