import {
	createPrivateKey,
	createPublicKey,
	generateKeyPairSync,
	randomUUID,
} from "node:crypto";
import {
	chmodSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { PROFILE, identitySchema, type Identity } from "./contracts.js";
import { publicKey, signRequest, thumbprint } from "./signatures.js";

export function loadOrCreateKey(path: string) {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	try {
		const { privateKey } = generateKeyPairSync("ec", {
			namedCurve: "prime256v1",
		});
		writeFileSync(path, privateKey.export({ format: "pem", type: "pkcs8" }), {
			flag: "wx",
			mode: 0o600,
		});
	} catch (error) {
		if (!(error instanceof Error && "code" in error && error.code === "EEXIST"))
			throw error;
	}
	const stat = lstatSync(path);
	if (!stat.isFile() || stat.isSymbolicLink())
		throw new Error("Use a regular private key file");
	chmodSync(path, 0o600);
	const key = createPrivateKey(readFileSync(path));
	if (
		key.asymmetricKeyType !== "ec" ||
		key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
	)
		throw new Error("Expected P-256 key");
	return key;
}
export class IdentityClient {
	readonly key;
	readonly publicKey;
	readonly keyId;
	constructor(
		keyPath: string,
		readonly allowLoopback = false,
	) {
		this.key = loadOrCreateKey(keyPath);
		this.publicKey = publicKey(
			createPublicKey(this.key).export({ format: "jwk" }),
		);
		this.keyId = `aithos-client:${thumbprint(this.publicKey)}`;
	}
	request(
		url: string,
		value: unknown,
		options: {
			requestId?: string;
			a2a?: boolean;
			a2aVersion?: string;
			created?: number;
		} = {},
	): Request {
		const body = Buffer.from(JSON.stringify(value));
		const headers: [string, string][] = [
			["content-type", "application/json"],
			["aithos-request-id", options.requestId ?? randomUUID()],
		];
		if (options.a2a)
			headers.push(
				["a2a-extensions", PROFILE],
				["a2a-version", options.a2aVersion ?? "1.0.0"],
			);
		const signed = signRequest({
			method: "POST",
			url,
			headers,
			body,
			keyId: this.keyId,
			key: this.key,
			allowLoopback: this.allowLoopback,
			...(options.created === undefined ? {} : { created: options.created }),
		});
		return new Request(url, { method: "POST", headers: signed, body });
	}
	async enroll(
		url: string,
		transport: (request: Request) => Promise<Response> = fetch,
	): Promise<Identity> {
		const response = await transport(
			this.request(url, { publicKey: this.publicKey }),
		);
		if (!response.ok) throw new Error(`Enrollment refused: ${response.status}`);
		return identitySchema.parse(await response.json());
	}
}
