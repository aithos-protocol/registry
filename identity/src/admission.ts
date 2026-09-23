import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import {
	PROFILE,
	ENROLLMENT,
	RULE_VERSION,
	IdentityError,
	eventSchema,
	fail,
	idSchema,
	problem,
	type AuditEvent,
	type Caller,
	type Provider,
	type Evaluation,
} from "./contracts.js";
import { boundedBody, deadline, RateLimiter, trustedUrl } from "./http.js";
import { parseProof, thumbprint, verifyProof } from "./signatures.js";
import type { Journal } from "./sqlite.js";
import { ExtensionRequired, extensionResponse } from "./a2a-errors.js";

interface Scope {
	caller: Caller;
	sessions: Set<string>;
}
export interface AdmissionOptions {
	merchantId: string;
	origin: string;
	enrollmentUrl: string;
	provider: Provider;
	journal: Journal;
	mode?: "challenge" | "restricted";
	allowLoopback?: boolean;
	now?: () => number;
	permissions?: readonly string[];
	maxRequestsPerMinute?: number;
	evaluate?: (evaluation: Evaluation) => readonly string[] | null;
}
const catalog = ["searchProducts", "getProductDetails"];
const defaults = [...catalog, "createCart", "updateCart", "getCartSummary"]; // No checkout/payment in this pilot.
const publicPaths = [
	"/",
	"/health",
	"/.well-known/agent-card.json",
	"/.well-known/ucp",
];
const protectedPaths = [
	"/",
	"/sessions",
	"/chat",
	"/message:send",
	"/commerce/a2a",
	"/commerce/customer",
];
export class Admission {
	private readonly scope = new AsyncLocalStorage<Scope>();
	private readonly limiter: RateLimiter;
	readonly extensions: readonly {
		uri: string;
		description: string;
		required: boolean;
		params?: Record<string, string>;
	}[];
	constructor(private readonly options: AdmissionOptions) {
		idSchema.parse(options.merchantId);
		trustedUrl(
			new Request(`${options.origin}/`),
			options.origin,
			options.allowLoopback,
		);
		trustedUrl(
			new Request(options.enrollmentUrl),
			new URL(options.enrollmentUrl).origin,
			options.allowLoopback,
		);
		this.limiter = new RateLimiter(options.maxRequestsPerMinute ?? 120);
		this.extensions = [
			{
				uri: PROFILE,
				description:
					"Sign each HTTP request with a locally persisted P-256 key.",
				required: options.mode !== "restricted",
			},
			{
				uri: ENROLLMENT,
				description:
					"Enroll a client identity; no Agent Card or public endpoint required.",
				required: false,
				params: {
					enrollmentUrl: options.enrollmentUrl,
					requestIdHeader: "Aithos-Request-Id",
				},
			},
		];
	}
	current(): Caller | undefined {
		return this.scope.getStore()?.caller;
	}
	allows(capability: string): boolean {
		return this.current()?.permissions.includes(capability) ?? false;
	}
	aroundSession<T>(sessionId: string, run: () => T): T {
		const scope = this.scope.getStore();
		if (!scope) fail(403, "no_caller");
		const event = this.event(
			"session_created",
			"session",
			"unknown",
			"unavailable",
			sessionId,
		);
		this.options.journal.append(event, false);
		try {
			const result = run();
			scope.sessions.add(sessionId);
			this.options.journal.finish({
				...event,
				outcome: "success",
				reason: "completed",
			});
			return result;
		} catch (error) {
			this.options.journal.finish({
				...event,
				outcome: "error",
				reason: "failed",
			});
			throw error;
		}
	}
	denyAction(operation: string, sessionId: string): void {
		this.options.journal.append(
			this.event("action", operation, "denied", "policy", sessionId),
		);
	}
	canResume(sessionId: string): boolean {
		const scope = this.scope.getStore();
		return (
			!!scope && (scope.caller.kind === "key" || scope.sessions.has(sessionId))
		);
	}
	async aroundAction<T>(
		operation: string,
		sessionId: string,
		run: () => Promise<T>,
	): Promise<T> {
		if (!this.allows(operation)) {
			this.options.journal.append(
				this.event("action", operation, "denied", "policy", sessionId),
			);
			fail(403, "policy");
		}
		const event = this.event(
			"action",
			operation,
			"unknown",
			"unavailable",
			sessionId,
		);
		this.options.journal.append(event, false);
		try {
			const result = await run();
			// The result may be merchant-policy blocked; do not claim success then.
			const denied =
				typeof result === "object" &&
				result !== null &&
				"status" in result &&
				result.status !== "ok";
			this.options.journal.finish({
				...event,
				outcome: denied ? "denied" : "success",
				reason: denied ? "policy" : "completed",
			});
			return result;
		} catch (error) {
			this.options.journal.finish({
				...event,
				outcome: "error",
				reason: "failed",
			});
			throw error;
		}
	}
	private event(
		type: AuditEvent["type"],
		operation: string,
		outcome: AuditEvent["outcome"],
		reason: AuditEvent["reason"],
		sessionId?: string,
	): AuditEvent {
		const caller = this.current();
		return eventSchema.parse({
			eventId: randomUUID(),
			requestId: caller?.requestId ?? randomUUID(),
			identityId: caller?.identityId ?? null,
			type,
			operation,
			outcome,
			reason,
			ruleVersion: RULE_VERSION,
			occurredAt: new Date(this.options.now?.() ?? Date.now()).toISOString(),
			...(sessionId ? { sessionId } : {}),
		});
	}
	async run(
		request: Request,
		next: (request: Request) => Promise<Response>,
	): Promise<Response> {
		const url = new URL(request.url);
		if (request.method === "GET" && publicPaths.includes(url.pathname))
			return next(request);
		let attribution: Pick<Caller, "identityId" | "requestId"> | undefined;
		try {
			this.limiter.check("all"); // Do not trust caller-controlled Forwarded/IP headers.
			if (request.method !== "POST" || !protectedPaths.includes(url.pathname))
				fail(403, "route_policy");
			const callerAndBody = await this.authenticate(request, (proven) => {
				attribution = proven;
			});
			const scope: Scope = {
				caller: callerAndBody.caller,
				sessions: new Set(),
			};
			return await this.scope.run(scope, async () => {
				this.options.journal.append(
					this.event(
						"admission",
						"request",
						"allowed",
						scope.caller.kind === "key" ? "authenticated" : "provisional",
					),
				);
				const interaction = this.event(
					"interaction",
					"request",
					"unknown",
					"unavailable",
				);
				this.options.journal.append(interaction, false);
				try {
					const response = await next(
						new Request(request.url, {
							method: request.method,
							headers: request.headers,
							body: Buffer.from(callerAndBody.body),
						}),
					);
					this.options.journal.finish({
						...interaction,
						outcome: response.ok ? "success" : "error",
						reason: response.ok ? "completed" : "failed",
					});
					const headers = new Headers(response.headers);
					headers.set("Aithos-Identity-Id", scope.caller.identityId);
					headers.set("Aithos-Identity-Kind", scope.caller.kind);
					headers.set(
						"Link",
						`<${this.options.enrollmentUrl}>; rel="aithos-enrollment"`,
					);
					if (scope.caller.kind === "key")
						headers.set(
							"A2A-Extensions",
							[headers.get("A2A-Extensions"), PROFILE]
								.filter(Boolean)
								.join(", "),
						);
					return new Response(response.body, {
						status: response.status,
						headers,
					});
				} catch (error) {
					this.options.journal.finish({
						...interaction,
						outcome: "error",
						reason: "failed",
					});
					throw error;
				}
			});
		} catch (error) {
			const code = error instanceof IdentityError ? error.code : "unavailable";
			const reason =
				code === "identity_required"
					? "missing_proof"
					: code === "policy" || code === "replay" || code === "invalid_proof"
						? code
						: "unavailable";
			try {
				this.options.journal.append({
					...this.event("admission", "request", "denied", reason),
					...attribution,
				});
			} catch {
				return problem(new IdentityError(503, "audit_unavailable"));
			}
			return error instanceof ExtensionRequired
				? extensionResponse(url.pathname, error.body)
				: problem(error, this.options.enrollmentUrl);
		}
	}
	private async authenticate(
		request: Request,
		proven: (caller: Pick<Caller, "identityId" | "requestId">) => void,
	): Promise<{ caller: Caller; body: Uint8Array }> {
		const body = await boundedBody(request);
		const hasProof = ["signature", "signature-input", "content-digest"].some(
			(h) => request.headers.has(h),
		);
		if (!hasProof) {
			if (this.options.mode !== "restricted") fail(401, "identity_required");
			const identity = await deadline(this.options.provider.provisional());
			return {
				body,
				caller: Object.freeze({
					identityId: identity.identityId,
					kind: "provisional",
					merchantId: this.options.merchantId,
					requestId: randomUUID(),
					permissions: Object.freeze([...catalog]),
				}),
			};
		}
		const proof = parseProof(
			request.method,
			trustedUrl(request, this.options.origin, this.options.allowLoopback),
			[...request.headers],
			["aithos-request-id"],
			this.options.allowLoopback,
		);
		const now = this.options.now?.() ?? Date.now();
		if (Math.abs(Math.floor(now / 1000) - proof.created) > 60)
			fail(401, "invalid_proof");
		const keyThumb = /^aithos-client:([A-Za-z0-9_-]{43})$/.exec(
			proof.keyId,
		)?.[1];
		if (!keyThumb) fail(401, "invalid_proof");
		const evaluation = await deadline(this.options.provider.resolve(keyThumb));
		if (
			!evaluation ||
			evaluation.identity.status !== "active" ||
			evaluation.identity.kind !== "key" ||
			!evaluation.identity.publicKey ||
			thumbprint(evaluation.identity.publicKey) !== keyThumb
		)
			fail(401, "invalid_proof");
		verifyProof(
			proof,
			evaluation.identity.publicKey,
			body,
			this.options.now?.() ?? Date.now(),
		);
		const requestId = request.headers.get("aithos-request-id");
		if (
			!idSchema.safeParse(requestId).success ||
			!requestId ||
			requestId.length < 16
		)
			fail(401, "invalid_proof");
		// Only a verified request can be attributed to an identity. A forged
		// keyid must never manufacture negative history for its claimed owner.
		proven({ identityId: evaluation.identity.identityId, requestId });
		const allowed = this.options.permissions ?? defaults;
		const evaluated = this.options.evaluate
			? this.options.evaluate(evaluation)
			: allowed;
		if (evaluated === null) fail(403, "policy");
		const permissions = allowed.filter((p) => evaluated.includes(p));
		const path = new URL(request.url).pathname;
		if (
			(path === "/" || path === "/message:send") &&
			!(request.headers.get("a2a-extensions") ?? "")
				.split(",")
				.map((s) => s.trim())
				.includes(PROFILE)
		)
			throw new ExtensionRequired(body);
		this.options.journal.claim(
			`${this.options.merchantId}:${evaluation.identity.identityId}`,
			requestId,
			(proof.created + 60) * 1000 + 999,
			now,
		);
		return {
			body,
			caller: Object.freeze({
				identityId: evaluation.identity.identityId,
				kind: "key",
				merchantId: this.options.merchantId,
				requestId,
				permissions: Object.freeze(permissions),
				evaluation,
			}),
		};
	}
	flush(): Promise<number> {
		return this.options.journal.flush(this.options.provider);
	}
}
