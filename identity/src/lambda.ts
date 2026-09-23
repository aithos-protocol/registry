import {
	SecretsManagerClient,
	GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import type {
	APIGatewayProxyEventV2,
	APIGatewayProxyStructuredResultV2,
} from "aws-lambda";
import { z } from "zod";
import { createProviderHandler } from "./provider.js";
import { DynamoIdentityStore } from "./dynamo.js";
import { idSchema } from "./contracts.js";

const environment = z
	.object({
		IDENTITY_ORIGIN: z.url(),
		IDENTITY_TABLE: z.string().min(1),
		IDENTITY_SECRET_ARN: z.string().min(1),
		IDENTITY_RETENTION_DAYS: z.coerce.number().int().min(1).max(365),
	})
	.parse(process.env);
const credentials = z.strictObject({
	partners: z
		.array(z.strictObject({ merchantId: idSchema, token: z.string().min(32) }))
		.min(1),
	adminToken: z.string().min(32),
});
const secrets = new SecretsManagerClient({});
const store = new DynamoIdentityStore(
	environment.IDENTITY_TABLE,
	undefined,
	environment.IDENTITY_RETENTION_DAYS,
);
let cached:
	| { until: number; handle: (request: Request) => Promise<Response> }
	| undefined;
export async function handler(
	event: APIGatewayProxyEventV2,
): Promise<APIGatewayProxyStructuredResultV2> {
	try {
		if (!cached || cached.until < Date.now()) {
			const secret = await secrets.send(
				new GetSecretValueCommand({
					SecretId: environment.IDENTITY_SECRET_ARN,
				}),
			);
			const config = credentials.parse(
				JSON.parse(secret.SecretString ?? "null"),
			);
			cached = {
				until: Date.now() + 60000,
				handle: createProviderHandler({
					origin: environment.IDENTITY_ORIGIN,
					store,
					retentionDays: environment.IDENTITY_RETENTION_DAYS,
					...config,
				}),
			};
		}
		const body = event.body
			? Buffer.from(event.body, event.isBase64Encoded ? "base64" : "utf8")
			: undefined;
		const url = `${environment.IDENTITY_ORIGIN}${event.rawPath}${event.rawQueryString ? `?${event.rawQueryString}` : ""}`;
		const headers = Object.entries(event.headers).filter(
			(entry): entry is [string, string] => typeof entry[1] === "string",
		);
		const request = new Request(url, {
			method: event.requestContext.http.method,
			headers,
			...(body ? { body } : {}),
		});
		const response = await cached.handle(request);
		if (response.status >= 500) console.error("identity_provider_unavailable");
		return {
			statusCode: response.status,
			headers: Object.fromEntries(response.headers),
			body: await response.text(),
		};
	} catch {
		// Never log request bodies, tokens or SDK exception objects carrying input.
		console.error("identity_provider_unavailable");
		return {
			statusCode: 503,
			headers: {
				"content-type": "application/json",
				"cache-control": "no-store",
			},
			body: '{"error":"unavailable"}',
		};
	}
}
