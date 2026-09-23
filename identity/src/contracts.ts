import { z } from "zod";

export const PROFILE =
	"https://aithos-protocol.github.io/agent-request-auth/v2";
export const ENROLLMENT =
	"https://aithos-protocol.github.io/client-identity/v0";
export const RULE_VERSION = "admission-v0.1";
export const idSchema = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);
export const thumbSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const publicKeySchema = z.strictObject({
	kty: z.literal("EC"),
	crv: z.literal("P-256"),
	x: thumbSchema,
	y: thumbSchema,
});
export type PublicKey = z.infer<typeof publicKeySchema>;
export const identitySchema = z.strictObject({
	identityId: idSchema,
	kind: z.enum(["key", "provisional"]),
	status: z.enum(["active", "revoked"]),
	publicKey: publicKeySchema.optional(),
	thumbprint: thumbSchema.optional(),
	createdAt: z.string().datetime(),
});
export type Identity = z.infer<typeof identitySchema>;
export const evaluationSchema = z.strictObject({
	identity: identitySchema,
	evidence: z.enum(["key-possession", "none"]),
	history: z.enum(["insufficient", "observed"]),
	interactions: z.number().int().nonnegative(),
	ruleVersion: z.literal(RULE_VERSION),
});
export type Evaluation = z.infer<typeof evaluationSchema>;
export const operations = [
	"request",
	"session",
	"searchProducts",
	"getProductDetails",
	"createCart",
	"updateCart",
	"getCartSummary",
	"prepareCheckoutHandoff",
	"completeCheckout",
	"mandate",
] as const;
export const eventSchema = z.strictObject({
	eventId: z.string().uuid(),
	requestId: idSchema,
	identityId: idSchema.nullable(),
	type: z.enum(["admission", "session_created", "action", "interaction"]),
	operation: z.enum(operations),
	outcome: z.enum(["allowed", "denied", "success", "error", "unknown"]),
	reason: z.enum([
		"authenticated",
		"provisional",
		"missing_proof",
		"invalid_proof",
		"revoked",
		"policy",
		"session_owner",
		"replay",
		"completed",
		"failed",
		"unavailable",
	]),
	occurredAt: z.string().datetime(),
	ruleVersion: z.literal(RULE_VERSION),
	sessionId: idSchema.optional(),
});
export type AuditEvent = z.infer<typeof eventSchema>;
export const eventBatchSchema = z.strictObject({
	events: z.array(eventSchema).min(1).max(100),
});
export const enrollmentSchema = z.strictObject({ publicKey: publicKeySchema });

export class IdentityError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
	) {
		super(code);
	}
}
export function fail(status: number, code: string): never {
	throw new IdentityError(status, code);
}
export function problem(error: unknown, enrollmentUrl?: string): Response {
	const known =
		error instanceof IdentityError
			? error
			: new IdentityError(503, "unavailable");
	return Response.json(
		{
			error: known.code,
			...(known.status === 401 && enrollmentUrl
				? {
						enrollment: {
							url: enrollmentUrl,
							profile: PROFILE,
							instruction:
								"Generate and securely persist a P-256 key locally. Enroll its public JWK with a signed request, then sign and retry this request. Reuse the same key on future visits. Never send your private key.",
						},
					}
				: {}),
		},
		{
			status: known.status,
			headers: {
				"cache-control": "no-store",
				...(known.status === 401
					? { "www-authenticate": 'AgentSignature realm="aithos"' }
					: {}),
			},
		},
	);
}
export interface IdentityStore {
	enroll(key: PublicKey, thumbprint: string): Promise<Identity>;
	provisional(merchantId: string): Promise<Identity>;
	resolve(thumbprint: string, merchantId: string): Promise<Evaluation | null>;
	revoke(identityId: string): Promise<void>;
	ingest(merchantId: string, events: AuditEvent[]): Promise<void>;
	events(merchantId: string, identityId: string): Promise<AuditEvent[]>;
}
export interface Provider {
	resolve(thumbprint: string): Promise<Evaluation | null>;
	provisional(): Promise<Identity>;
	ingest(events: AuditEvent[]): Promise<void>;
}
export interface Caller {
	readonly identityId: string;
	readonly merchantId: string;
	readonly requestId: string;
	readonly kind: "key" | "provisional";
	readonly permissions: readonly string[];
	readonly evaluation?: Evaluation;
}
