import {
	createHash,
	createPublicKey,
	sign,
	verify,
	type KeyObject,
} from "node:crypto";
import { serializeInnerList, type InnerList } from "structured-headers";
import { PROFILE, fail, publicKeySchema, type PublicKey } from "./contracts.js";
import { strictDictionary } from "./structured.js";

export type HeaderPairs = readonly (readonly [string, string])[];
const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const required = ["@method", "@target-uri", "content-digest"];
const whenPresent = [
	"content-type",
	"content-encoding",
	"a2a-extensions",
	"a2a-version",
];
const order = BigInt(
	"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);
export const digest = (data: Uint8Array | string) =>
	createHash("sha256").update(data).digest();
export function publicKey(value: unknown): PublicKey {
	const result = publicKeySchema.safeParse(value);
	if (!result.success) fail(401, "invalid_proof");
	const key = result.data;
	for (const coordinate of [key.x, key.y]) {
		const bytes = Buffer.from(coordinate, "base64url");
		if (bytes.length !== 32 || bytes.toString("base64url") !== coordinate)
			fail(401, "invalid_proof");
	}
	try {
		createPublicKey({ key, format: "jwk" });
	} catch {
		fail(401, "invalid_proof");
	}
	return key;
}
export function thumbprint(key: PublicKey): string {
	const { crv, kty, x, y } = publicKey(key);
	return digest(JSON.stringify({ crv, kty, x, y })).toString("base64url");
}
function fields(pairs: HeaderPairs): Map<string, string> {
	const output = new Map<string, string>();
	for (const [raw, value] of pairs) {
		if (!token.test(raw) || /[^\x09\x20-\x7e]/.test(value))
			fail(401, "invalid_proof");
		const name = raw.toLowerCase(),
			previous = output.get(name);
		if (
			previous !== undefined &&
			["content-type", "a2a-version", "aithos-request-id"].includes(name)
		)
			fail(401, "invalid_proof");
		output.set(
			name,
			previous === undefined ? value.trim() : `${previous}, ${value.trim()}`,
		);
	}
	return output;
}
export function canonicalTarget(url: string, allowLoopback = false): string {
	if (/[^\x21-\x7e]|\\|#|%(?![\da-fA-F]{2})/.test(url))
		fail(401, "invalid_proof");
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return fail(401, "invalid_proof");
	}
	const local =
		allowLoopback &&
		parsed.protocol === "http:" &&
		parsed.hostname === "127.0.0.1";
	if (
		(!local && parsed.protocol !== "https:") ||
		parsed.username ||
		parsed.password
	)
		fail(401, "invalid_proof");
	// Avoid WHATWG reserialization: escapes, query order and case are signed.
	const match = /^(https?):\/\/([^/?#]+)([^?#]*)(\?[^#]*)?$/.exec(url);
	if (!match) fail(401, "invalid_proof");
	return `${match[1]}://${match[2]}${match[3] || "/"}${match[4] || ""}`;
}
function base(
	method: string,
	url: string,
	headers: Map<string, string>,
	input: InnerList,
): Buffer {
	const lines = input[0].map(([name]) => {
		const value =
			name === "@method"
				? method
				: name === "@target-uri"
					? url
					: headers.get(String(name));
		if (value === undefined) fail(401, "invalid_proof");
		return `${JSON.stringify(name)}: ${value}`;
	});
	lines.push(`"@signature-params": ${serializeInnerList(input)}`);
	return Buffer.from(lines.join("\n"), "ascii");
}
export interface ParsedProof {
	keyId: string;
	created: number;
	signature: Buffer;
	base: Buffer;
	contentDigest: Buffer;
}
export function parseProof(
	method: string,
	url: string,
	pairs: HeaderPairs,
	extra: string[] = [],
	allowLoopback = false,
): ParsedProof {
	if (!token.test(method)) fail(401, "invalid_proof");
	const target = canonicalTarget(url, allowLoopback),
		headers = fields(pairs);
	const inputs = strictDictionary(headers.get("signature-input") ?? "");
	const signatures = strictDictionary(headers.get("signature") ?? "");
	if (
		inputs.size !== signatures.size ||
		[...inputs.keys()].some((k) => !signatures.has(k))
	)
		fail(401, "invalid_proof");
	if (
		[...inputs.values()].some(([v]) => !Array.isArray(v)) ||
		[...signatures.values()].some(
			([v, p]) => !(v instanceof ArrayBuffer) || p.size,
		)
	)
		fail(401, "invalid_proof");
	const candidates = [...inputs].filter(([, v]) => v[1].get("tag") === PROFILE);
	if (candidates.length !== 1) fail(401, "invalid_proof");
	const [label, input] = candidates[0]!;
	if (!Array.isArray(input[0])) fail(401, "invalid_proof");
	const selected: InnerList = [input[0], input[1]];
	const params = selected[1],
		created = params.get("created"),
		keyId = params.get("keyid");
	if (
		typeof created !== "number" ||
		!Number.isInteger(created) ||
		created < 0 ||
		typeof keyId !== "string" ||
		!/^[\x21-\x7e]{1,512}$/.test(keyId)
	)
		fail(401, "invalid_proof");
	if (
		[...params.keys()].some(
			(k) => !["created", "keyid", "tag", "alg"].includes(k),
		) ||
		(params.has("alg") && params.get("alg") !== "ecdsa-p256-sha256")
	)
		fail(401, "invalid_proof");
	// SF decimals lose their type in structured-headers. Reject decimal created
	// parameters before accepting the profile's required integer representation.
	if (/;\s*created=-?\d+\./.test(headers.get("signature-input") ?? ""))
		fail(401, "invalid_proof");
	const names = selected[0].map(([n, p]) => {
		if (
			typeof n !== "string" ||
			p.size ||
			(!required.includes(n) && (!token.test(n) || n !== n.toLowerCase()))
		)
			fail(401, "invalid_proof");
		return n;
	});
	if (
		new Set(names).size !== names.length ||
		[...required, ...extra, ...whenPresent.filter((h) => headers.has(h))].some(
			(h) => !names.includes(h),
		)
	)
		fail(401, "invalid_proof");
	const digests = strictDictionary(headers.get("content-digest") ?? "");
	if ([...digests.values()].some(([v]) => !(v instanceof ArrayBuffer)))
		fail(401, "invalid_proof");
	const content = digests.get("sha-256"),
		signature = signatures.get(label);
	if (
		!content ||
		!(content[0] instanceof ArrayBuffer) ||
		content[0].byteLength !== 32 ||
		content[1].size ||
		!signature ||
		!(signature[0] instanceof ArrayBuffer) ||
		signature[1].size ||
		signature[0].byteLength !== 64
	)
		fail(401, "invalid_proof");
	const bytes = Buffer.from(signature[0]);
	for (const chunk of [bytes.subarray(0, 32), bytes.subarray(32)]) {
		const value = BigInt(`0x${chunk.toString("hex")}`);
		if (value < 1n || value >= order) fail(401, "invalid_proof");
	}
	return {
		keyId,
		created,
		signature: bytes,
		base: base(method, target, headers, selected),
		contentDigest: Buffer.from(content[0]),
	};
}
export function verifyProof(
	proof: ParsedProof,
	key: PublicKey,
	body: Uint8Array,
	now = Date.now(),
): void {
	if (
		Math.abs(Math.floor(now / 1000) - proof.created) > 60 ||
		!digest(body).equals(proof.contentDigest)
	)
		fail(401, "invalid_proof");
	const valid = verify(
		"sha256",
		proof.base,
		{
			key: createPublicKey({ key: publicKey(key), format: "jwk" }),
			dsaEncoding: "ieee-p1363",
		},
		proof.signature,
	);
	if (!valid) fail(401, "invalid_proof");
}
export function signRequest(input: {
	method: string;
	url: string;
	headers: HeaderPairs;
	body: Uint8Array;
	keyId: string;
	key: KeyObject;
	created?: number;
	allowLoopback?: boolean;
}): [string, string][] {
	const pairs: [string, string][] = input.headers.map(([k, v]) => [k, v]);
	if (fields(pairs).has("signature") || fields(pairs).has("signature-input"))
		throw new Error(
			"Sign before other signature schemes; merging is not supported by this client helper",
		);
	pairs.push([
		"content-digest",
		`sha-256=:${digest(input.body).toString("base64")}:`,
	]);
	const headers = fields(pairs);
	const names = [
		...required,
		...whenPresent.filter((h) => headers.has(h)),
		...(headers.has("aithos-request-id") ? ["aithos-request-id"] : []),
	];
	const selected: InnerList = [
		names.map((n) => [n, new Map()]),
		new Map<string, string | number>([
			["created", input.created ?? Math.floor(Date.now() / 1000)],
			["keyid", input.keyId],
			["tag", PROFILE],
		]),
	];
	const target = canonicalTarget(input.url, input.allowLoopback);
	const signature = sign(
		"sha256",
		base(input.method, target, headers, selected),
		{ key: input.key, dsaEncoding: "ieee-p1363" },
	);
	pairs.push(
		["signature-input", `sig1=${serializeInnerList(selected)}`],
		["signature", `sig1=:${signature.toString("base64")}:`],
	);
	return pairs;
}
