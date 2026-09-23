import { execFileSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
	SecretsManagerClient,
	DescribeSecretCommand,
	PutSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { z } from "zod";

// Run with validated registry-dev credentials. Never prints a credential or
// sends one in shell arguments; secret values never enter Terraform state.
const output = z
	.object({
		origin: z.object({ value: z.url() }),
		secret_arn: z.object({ value: z.string() }),
	})
	.parse(
		JSON.parse(
			execFileSync("terraform", ["-chdir=infra", "output", "-json"], {
				encoding: "utf8",
			}),
		),
	);
const client = new SecretsManagerClient({});
const path = ".local/dev-access.json";
const schema = z.object({
	origin: z.url(),
	secretArn: z.string(),
	clientRequestToken: z.string().uuid(),
	partners: z.array(z.object({ merchantId: z.string(), token: z.string() })),
	adminToken: z.string(),
});
mkdirSync(".local", { recursive: true, mode: 0o700 });
const metadata = await client.send(
	new DescribeSecretCommand({ SecretId: output.secret_arn.value }),
);
if (Object.keys(metadata.VersionIdsToStages ?? {}).length && !existsSync(path))
	throw new Error(
		"Secret already provisioned: refusing to rotate it or retrieve unknown credentials",
	);
const config = existsSync(path)
	? schema.parse(JSON.parse(readFileSync(path, "utf8")))
	: {
			origin: output.origin.value,
			secretArn: output.secret_arn.value,
			clientRequestToken: randomUUID(),
			partners: ["shop", "other"].map((merchantId) => ({
				merchantId,
				token: randomBytes(32).toString("base64url"),
			})),
			adminToken: randomBytes(32).toString("base64url"),
		};
if (
	config.origin !== output.origin.value ||
	config.secretArn !== output.secret_arn.value
)
	throw new Error("Local deployment mismatch");
if (!existsSync(path))
	writeFileSync(path, JSON.stringify(config), { mode: 0o600, flag: "wx" });
await client.send(
	new PutSecretValueCommand({
		SecretId: config.secretArn,
		ClientRequestToken: config.clientRequestToken,
		SecretString: JSON.stringify({
			partners: config.partners,
			adminToken: config.adminToken,
		}),
	}),
);
console.log(
	JSON.stringify({
		origin: config.origin,
		credentialFile: path,
		provisioned: true,
	}),
);
