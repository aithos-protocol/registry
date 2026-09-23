import { expect, test } from "bun:test";
import { boundedBody, deadline, RateLimiter, trustedUrl } from "../src/http.js";

test("bounded input rejects oversized headers and streamed bodies", async () => {
	await expect(
		boundedBody(
			new Request("https://seller.test", {
				headers: { "x-large": "x".repeat(16385) },
			}),
		),
	).rejects.toThrow("headers_too_large");
	await expect(boundedBody(new Response("12345"), 4)).rejects.toThrow(
		"body_too_large",
	);
	expect(
		Buffer.from(await boundedBody(new Response("1234"), 4)).toString(),
	).toBe("1234");
});
test("never-ending bodies and provider callbacks have finite deadlines", async () => {
	await expect(
		boundedBody(new Response(new ReadableStream({ start() {} })), 100, 10),
	).rejects.toThrow("body_timeout");
	await expect(deadline(new Promise(() => {}), 10)).rejects.toThrow(
		"provider_timeout",
	);
});
test("proxy origin is configured, never taken from untrusted headers", () => {
	expect(
		trustedUrl(
			new Request("http://internal.invalid/sessions?a=%2F", {
				headers: { forwarded: "host=evil.test;proto=https" },
			}),
			"https://seller.test",
		),
	).toBe("https://seller.test/sessions?a=%2F");
	expect(() =>
		trustedUrl(new Request("http://127.0.0.1/"), "http://127.0.0.1"),
	).toThrow();
});
test("throttle cardinality is bounded and windows expire", () => {
	const limiter = new RateLimiter(1, 1);
	limiter.check("first", 0);
	expect(() => limiter.check("first", 1)).toThrow("rate_limited");
	expect(() => limiter.check("second", 1)).toThrow("rate_limited");
	limiter.check("second", 60001);
});
