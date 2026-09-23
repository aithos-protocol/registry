import { describe, expect, test } from "bun:test";
import { createPublicKey, verify } from "node:crypto";
import { z } from "zod";
import vectors from "./vectors/profile-v2.json";
import rfc from "./vectors/rfc9421-b24.json";
import {
	parseProof,
	publicKey,
	thumbprint,
	verifyProof,
} from "../src/signatures.js";

const pairs = z.array(z.tuple([z.string(), z.string()]));
const key = publicKey(vectors.public_jwk);
describe("shared agent-request-auth/v2 conformance", () => {
	test("RFC 7638 thumbprint", () =>
		expect(thumbprint(key)).toBe(vectors.key_thumbprint));
	for (const vector of vectors.vectors) {
		test(vector.id, () => {
			const proof = parseProof(
				vector.method,
				vector.url,
				pairs.parse(vector.headers),
			);
			expect(proof.base.toString()).toBe(vector.signature_base);
			verifyProof(
				proof,
				key,
				Buffer.from(vector.body_base64, "base64"),
				1700000000000,
			);
		});
	}
	for (const mutation of vectors.mutations) {
		test(mutation.id, () => {
			const vector = vectors.vectors.find((v) => v.id === mutation.vector)!;
			let method = vector.method,
				url = vector.url,
				headers = pairs.parse(vector.headers),
				body = Buffer.from(vector.body_base64, "base64");
			if (mutation.change === "append-body-byte")
				body = Buffer.concat([body, Buffer.from([0])]);
			if (mutation.change === "method") method = mutation.value!;
			if (mutation.change === "url") url = mutation.value!;
			if (mutation.change === "header")
				headers = headers.map(([n, v]) => [
					n,
					n.toLowerCase() === mutation.name?.toLowerCase()
						? mutation.value!
						: v,
				]);
			if (mutation.change === "append-header")
				headers.push([mutation.name!, mutation.value!]);
			expect(() =>
				verifyProof(parseProof(method, url, headers), key, body, 1700000000000),
			).toThrow();
		});
	}
	test("independent RFC 9421 B.2.4 primitive", () => {
		expect(
			verify(
				"sha256",
				Buffer.from(rfc.signature_base),
				{
					key: createPublicKey({ key: rfc.public_jwk, format: "jwk" }),
					dsaEncoding: "ieee-p1363",
				},
				Buffer.from(rfc.signature_base64, "base64"),
			),
		).toBe(true);
	});
	test.each([
		"created=1700000000;created=1700000000",
		"created=1700000000.0",
	])("reject ambiguous parameters: %s", (replacement) => {
		const vector = vectors.vectors[0]!;
		const headers = pairs
			.parse(vector.headers)
			.map(([n, v]): [string, string] => [
				n,
				n === "Signature-Input"
					? v.replace("created=1700000000", replacement)
					: v,
			]);
		expect(() => parseProof(vector.method, vector.url, headers)).toThrow();
	});
	test("private and invalid public JWK rejected", () => {
		expect(() => publicKey({ ...key, d: "secret" })).toThrow();
		expect(() =>
			publicKey({ ...key, x: "A".repeat(43), y: "A".repeat(43) }),
		).toThrow();
	});
});
