import { fail } from "./contracts.js";

export function trustedUrl(
	request: Request,
	origin: string,
	allowLoopback = false,
): string {
	const configured = new URL(origin);
	if (
		configured.origin !== origin ||
		(configured.protocol !== "https:" &&
			!(
				allowLoopback &&
				configured.hostname === "127.0.0.1" &&
				configured.protocol === "http:"
			))
	)
		throw new Error(
			"Configure an explicit HTTPS origin (loopback only in local tests)",
		);
	// Forwarded/X-Forwarded-* are deliberately ignored. Deploy at the same path
	// without a stripping proxy; configure the externally visible origin.
	const incoming = new URL(request.url);
	return `${origin}${incoming.pathname}${incoming.search}`;
}
export async function boundedBody(
	request: Request | Response,
	limit = 1024 * 1024,
	timeout = 5000,
): Promise<Uint8Array> {
	const headerBytes = [...request.headers].reduce(
		(size, [k, v]) => size + k.length + v.length + 4,
		0,
	);
	if (headerBytes > 16384) fail(431, "headers_too_large");
	if (!request.body) return new Uint8Array();
	const reader = request.body.getReader();
	const started = Date.now();
	const chunks: Uint8Array[] = [];
	let size = 0;
	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			void reader.cancel();
			reject(new Error("body_timeout"));
		}, timeout);
	});
	try {
		while (true) {
			const { done, value } = await Promise.race([reader.read(), deadline]);
			if (done) break;
			size += value.byteLength;
			if (size > limit) {
				void reader.cancel();
				fail(413, "body_too_large");
			}
			chunks.push(value);
		}
	} catch (error) {
		if (error instanceof Error && error.message === "body_timeout")
			fail(408, "body_timeout");
		throw error;
	} finally {
		clearTimeout(timer);
		reader.releaseLock();
	}
	if (Date.now() - started >= timeout) fail(408, "body_timeout");
	return Buffer.concat(chunks);
}
export async function deadline<T>(work: Promise<T>, ms = 5000): Promise<T> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const start = Date.now();
	try {
		const value = await Promise.race([
			work,
			new Promise<never>((_, reject) => {
				timer = setTimeout(() => reject(new Error("provider_timeout")), ms);
			}),
		]);
		if (Date.now() - start > ms) fail(503, "unavailable");
		return value;
	} finally {
		clearTimeout(timer);
	}
}
export class RateLimiter {
	private buckets = new Map<string, { count: number; until: number }>();
	constructor(
		private readonly max = 120,
		private readonly maxBuckets = 10000,
	) {}
	check(key: string, now = Date.now()): void {
		for (const [id, bucket] of this.buckets)
			if (bucket.until <= now) this.buckets.delete(id);
		const bucket = this.buckets.get(key) ?? { count: 0, until: now + 60000 };
		if (
			(!this.buckets.has(key) && this.buckets.size >= this.maxBuckets) ||
			++bucket.count > this.max
		)
			fail(429, "rate_limited");
		this.buckets.set(key, bucket);
	}
}
