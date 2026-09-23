import { randomUUID } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
	DynamoDBDocumentClient,
	GetCommand,
	PutCommand,
	QueryCommand,
	TransactWriteCommand,
} from "@aws-sdk/lib-dynamodb";
import { z } from "zod";
import {
	identitySchema,
	eventSchema,
	RULE_VERSION,
	fail,
	type IdentityStore,
	type Identity,
	type Evaluation,
	type PublicKey,
	type AuditEvent,
} from "./contracts.js";

/** Separate private table; never touches the public Agent Card registry. */
export class DynamoIdentityStore implements IdentityStore {
	constructor(
		readonly table: string,
		readonly client = DynamoDBDocumentClient.from(new DynamoDBClient({})),
		readonly retentionDays = 7,
	) {
		if (
			!table ||
			!Number.isInteger(retentionDays) ||
			retentionDays < 1 ||
			retentionDays > 365
		)
			throw new Error("Invalid private store configuration");
	}
	private async get(pk: string, sk = "META") {
		return (
			await this.client.send(
				new GetCommand({
					TableName: this.table,
					Key: { pk, sk },
					ConsistentRead: true,
				}),
			)
		).Item;
	}
	async enroll(publicKey: PublicKey, thumbprint: string): Promise<Identity> {
		const previous = await this.get(`KEY#${thumbprint}`);
		if (previous) return active(previous.identity);
		const identity: Identity = {
			identityId: `idn_${randomUUID()}`,
			kind: "key",
			status: "active",
			publicKey,
			thumbprint,
			createdAt: new Date().toISOString(),
		};
		try {
			await this.client.send(
				new TransactWriteCommand({
					TransactItems: [
						{
							Put: {
								TableName: this.table,
								Item: { pk: `KEY#${thumbprint}`, sk: "META", identity },
								ConditionExpression: "attribute_not_exists(pk)",
							},
						},
						{
							Put: {
								TableName: this.table,
								Item: { pk: `ID#${identity.identityId}`, sk: "META", identity },
								ConditionExpression: "attribute_not_exists(pk)",
							},
						},
					],
				}),
			);
		} catch (error) {
			const concurrent = await this.get(`KEY#${thumbprint}`);
			if (concurrent) return active(concurrent.identity);
			throw error;
		}
		return identity;
	}
	async provisional(merchantId: string): Promise<Identity> {
		const identity: Identity = {
			identityId: `tmp_${randomUUID()}`,
			kind: "provisional",
			status: "active",
			createdAt: new Date().toISOString(),
		};
		await this.client.send(
			new PutCommand({
				TableName: this.table,
				Item: {
					pk: `ID#${identity.identityId}`,
					sk: "META",
					identity,
					merchantId,
					expiresAt: Math.floor(Date.now() / 1000) + this.retentionDays * 86400,
				},
				ConditionExpression: "attribute_not_exists(pk)",
			}),
		);
		return identity;
	}
	async resolve(
		thumbprint: string,
		merchantId: string,
	): Promise<Evaluation | null> {
		const row = await this.get(`KEY#${thumbprint}`);
		if (!row) return null;
		const identity = identitySchema.parse(row.identity);
		const counts = await this.get(
			`M#${merchantId}#${identity.identityId}`,
			"COUNT",
		);
		const interactions = z
			.number()
			.int()
			.nonnegative()
			.parse(counts?.interactions ?? 0);
		return {
			identity,
			evidence: "key-possession",
			interactions,
			history: interactions ? "observed" : "insufficient",
			ruleVersion: RULE_VERSION,
		};
	}
	async revoke(identityId: string): Promise<void> {
		const row = await this.get(`ID#${identityId}`);
		if (!row) fail(404, "not_found");
		const identity = identitySchema.parse(row.identity);
		const keys = [
			`ID#${identityId}`,
			...(identity.thumbprint ? [`KEY#${identity.thumbprint}`] : []),
		];
		await this.client.send(
			new TransactWriteCommand({
				TransactItems: keys.map((pk) => ({
					Update: {
						TableName: this.table,
						Key: { pk, sk: "META" },
						UpdateExpression: "SET #i.#s = :revoked",
						ConditionExpression: "attribute_exists(pk)",
						ExpressionAttributeNames: { "#i": "identity", "#s": "status" },
						ExpressionAttributeValues: { ":revoked": "revoked" },
					},
				})),
			}),
		);
	}
	async ingest(merchantId: string, events: AuditEvent[]): Promise<void> {
		// Each event is atomic; a partial batch may be retried safely by its sender.
		for (const input of events)
			await this.ingestOne(merchantId, eventSchema.parse(input));
	}
	private async ingestOne(
		merchantId: string,
		event: AuditEvent,
	): Promise<void> {
		const pk = `M#${merchantId}#${event.identityId ?? "unattributed"}`,
			sk = `E#${event.eventId}`;
		const payload = JSON.stringify(event);
		const existing = await this.get(pk, sk);
		if (existing) {
			if (existing.payload !== payload) fail(409, "event_conflict");
			return;
		}
		if (event.identityId) {
			const owner = await this.get(`ID#${event.identityId}`);
			if (
				!owner ||
				(owner.merchantId !== undefined && owner.merchantId !== merchantId)
			)
				fail(403, "identity_scope");
		}
		const expiresAt =
			Math.floor(Date.now() / 1000) + this.retentionDays * 86400;
		const items: NonNullable<
			ConstructorParameters<typeof TransactWriteCommand>[0]["TransactItems"]
		> = [
			{
				Put: {
					TableName: this.table,
					Item: { pk, sk, payload, expiresAt },
					ConditionExpression: "attribute_not_exists(pk)",
				},
			},
		];
		if (event.identityId)
			items.push({
				ConditionCheck: {
					TableName: this.table,
					Key: { pk: `ID#${event.identityId}`, sk: "META" },
					ConditionExpression:
						"attribute_exists(pk) AND (attribute_not_exists(merchantId) OR merchantId = :merchant)",
					ExpressionAttributeValues: { ":merchant": merchantId },
				},
			});
		if (event.type === "interaction" && event.identityId)
			items.push({
				Update: {
					TableName: this.table,
					Key: { pk, sk: "COUNT" },
					UpdateExpression: "ADD interactions :one",
					ExpressionAttributeValues: { ":one": 1 },
				},
			});
		try {
			await this.client.send(
				new TransactWriteCommand({ TransactItems: items }),
			);
		} catch (error) {
			const duplicate = await this.get(pk, sk);
			if (duplicate?.payload === payload) return;
			if (duplicate) fail(409, "event_conflict");
			throw error;
		}
	}
	async events(merchantId: string, identityId: string): Promise<AuditEvent[]> {
		const result = await this.client.send(
			new QueryCommand({
				TableName: this.table,
				KeyConditionExpression: "pk = :pk AND begins_with(sk, :event)",
				ExpressionAttributeValues: {
					":pk": `M#${merchantId}#${identityId}`,
					":event": "E#",
				},
				ConsistentRead: true,
				Limit: 1000,
			}),
		);
		// TTL deletion is asynchronous; expired audit data must disappear from the
		// API immediately, even while DynamoDB still retains the physical item.
		return (result.Items ?? [])
			.filter(
				(row) =>
					z.number().parse(row.expiresAt) > Math.floor(Date.now() / 1000),
			)
			.map((row) =>
				eventSchema.parse(JSON.parse(z.string().parse(row.payload))),
			);
	}
}
function active(value: unknown): Identity {
	const identity = identitySchema.parse(value);
	if (identity.status !== "active") fail(401, "invalid_proof");
	return identity;
}
