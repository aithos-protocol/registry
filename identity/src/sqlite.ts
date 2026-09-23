import { Database } from "bun:sqlite";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import {
	eventSchema,
	identitySchema,
	RULE_VERSION,
	fail,
	type AuditEvent,
	type Evaluation,
	type Identity,
	type IdentityStore,
	type Provider,
	type PublicKey,
} from "./contracts.js";

function open(path: string): Database {
	if (path !== ":memory:")
		mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const db = new Database(path, { create: true, strict: true });
	if (path !== ":memory:") chmodSync(path, 0o600);
	db.exec(
		"PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;",
	);
	return db;
}
export class SqliteIdentityStore implements IdentityStore {
	readonly db: Database;
	constructor(
		path: string,
		private readonly now: () => Date = () => new Date(),
	) {
		this.db = open(path);
		this.db.exec(`CREATE TABLE IF NOT EXISTS identities (id TEXT PRIMARY KEY, thumb TEXT UNIQUE, merchant TEXT, payload TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events (merchant TEXT NOT NULL, id TEXT NOT NULL, identity TEXT, payload TEXT NOT NULL, received TEXT NOT NULL, PRIMARY KEY(merchant,id));
      CREATE INDEX IF NOT EXISTS events_identity ON events(merchant,identity);`);
	}
	async enroll(key: PublicKey, thumbprint: string): Promise<Identity> {
		return this.db
			.transaction(() => {
				const existing = this.byThumb(thumbprint);
				if (existing) {
					if (existing.status === "revoked") fail(401, "invalid_proof");
					return existing;
				}
				const identity: Identity = {
					identityId: `idn_${randomUUID()}`,
					kind: "key",
					status: "active",
					publicKey: key,
					thumbprint,
					createdAt: this.now().toISOString(),
				};
				this.db
					.query("INSERT INTO identities (id,thumb,payload) VALUES (?,?,?)")
					.run(identity.identityId, thumbprint, JSON.stringify(identity));
				return identity;
			})
			.immediate();
	}
	async provisional(merchantId: string): Promise<Identity> {
		const identity: Identity = {
			identityId: `tmp_${randomUUID()}`,
			kind: "provisional",
			status: "active",
			createdAt: this.now().toISOString(),
		};
		this.db
			.query("INSERT INTO identities (id,merchant,payload) VALUES (?,?,?)")
			.run(identity.identityId, merchantId, JSON.stringify(identity));
		return identity;
	}
	byThumb(thumb: string): Identity | null {
		const row = this.db
			.query<{ payload: string }, [string]>(
				"SELECT payload FROM identities WHERE thumb=?",
			)
			.get(thumb);
		return row ? identitySchema.parse(JSON.parse(row.payload)) : null;
	}
	async resolve(thumb: string, merchant: string): Promise<Evaluation | null> {
		const identity = this.byThumb(thumb);
		if (!identity) return null;
		const { interactions } = this.db
			.query<{ interactions: number }, [string, string]>(
				"SELECT count(*) AS interactions FROM events WHERE merchant=? AND identity=? AND json_extract(payload,'$.type')='interaction'",
			)
			.get(merchant, identity.identityId)!;
		return {
			identity,
			evidence: "key-possession",
			interactions,
			history: interactions ? "observed" : "insufficient",
			ruleVersion: RULE_VERSION,
		};
	}
	async revoke(id: string): Promise<void> {
		this.db
			.transaction(() => {
				const row = this.db
					.query<{ payload: string }, [string]>(
						"SELECT payload FROM identities WHERE id=?",
					)
					.get(id);
				if (!row) fail(404, "not_found");
				const identity = identitySchema.parse(JSON.parse(row.payload));
				this.db
					.query("UPDATE identities SET payload=? WHERE id=?")
					.run(JSON.stringify({ ...identity, status: "revoked" }), id);
			})
			.immediate();
	}
	async ingest(merchant: string, events: AuditEvent[]): Promise<void> {
		this.db
			.transaction(() => {
				for (const input of events) {
					const event = eventSchema.parse(input);
					if (event.identityId) {
						const owner = this.db
							.query<{ merchant: string | null }, [string]>(
								"SELECT merchant FROM identities WHERE id=?",
							)
							.get(event.identityId);
						if (
							!owner ||
							(owner.merchant !== null && owner.merchant !== merchant)
						)
							fail(403, "identity_scope");
					}
					const encoded = JSON.stringify(event);
					const existing = this.db
						.query<{ payload: string }, [string, string]>(
							"SELECT payload FROM events WHERE merchant=? AND id=?",
						)
						.get(merchant, event.eventId);
					if (existing && existing.payload !== encoded)
						fail(409, "event_conflict");
					this.db
						.query("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?)")
						.run(
							merchant,
							event.eventId,
							event.identityId,
							encoded,
							this.now().toISOString(),
						);
				}
			})
			.immediate();
	}
	async events(merchant: string, identity: string): Promise<AuditEvent[]> {
		return this.db
			.query<{ payload: string }, [string, string]>(
				"SELECT payload FROM events WHERE merchant=? AND identity=? ORDER BY received,id LIMIT 1000",
			)
			.all(merchant, identity)
			.map((r) => eventSchema.parse(JSON.parse(r.payload)));
	}
	close(): void {
		this.db.close();
	}
}

export interface Journal {
	claim(scope: string, nonce: string, expires: number, now: number): void;
	append(event: AuditEvent, ready?: boolean): void;
	finish(event: AuditEvent): void;
	flush(provider: Provider): Promise<number>;
}
export class SqliteJournal implements Journal {
	readonly db: Database;
	private flushing: Promise<number> | undefined;
	constructor(
		path: string,
		readonly capacity = 10000,
	) {
		if (!Number.isInteger(capacity) || capacity < 2)
			throw new Error("Invalid journal capacity");
		this.db = open(path);
		this.db.exec(`CREATE TABLE IF NOT EXISTS requests (scope TEXT, nonce TEXT, expires INTEGER, PRIMARY KEY(scope,nonce));
      CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, payload TEXT NOT NULL, ready INTEGER NOT NULL);`);
		// One journal per server process. At startup unfinished operations have an
		// unknown outcome, not an invented success. Multi-process sharing forbidden.
		this.db.exec("UPDATE outbox SET ready=1 WHERE ready=0");
	}
	claim(scope: string, nonce: string, expires: number, now: number): void {
		this.db
			.transaction(() => {
				this.db.query("DELETE FROM requests WHERE expires < ?").run(now);
				const inserted = this.db
					.query("INSERT OR IGNORE INTO requests VALUES (?,?,?)")
					.run(scope, nonce, expires);
				if (!inserted.changes) fail(409, "replay");
			})
			.immediate();
	}
	append(event: AuditEvent, ready = true): void {
		this.db
			.transaction(() => {
				const { count } = this.db
					.query<{ count: number }, []>("SELECT count(*) as count FROM outbox")
					.get()!;
				if (count >= this.capacity) fail(503, "audit_capacity");
				this.db
					.query("INSERT INTO outbox VALUES (?,?,?)")
					.run(
						event.eventId,
						JSON.stringify(eventSchema.parse(event)),
						Number(ready),
					);
			})
			.immediate();
	}
	finish(event: AuditEvent): void {
		const updated = this.db
			.query("UPDATE outbox SET payload=?,ready=1 WHERE id=? AND ready=0")
			.run(JSON.stringify(eventSchema.parse(event)), event.eventId);
		if (!updated.changes) fail(503, "audit_unavailable");
	}
	flush(provider: Provider): Promise<number> {
		if (this.flushing) return this.flushing;
		this.flushing = this.deliver(provider).finally(() => {
			this.flushing = undefined;
		});
		return this.flushing;
	}
	private async deliver(provider: Provider): Promise<number> {
		const rows = this.db
			.query<{ payload: string }, []>(
				"SELECT payload FROM outbox WHERE ready=1 ORDER BY rowid LIMIT 100",
			)
			.all();
		const events = rows.map((r) => eventSchema.parse(JSON.parse(r.payload)));
		if (!events.length) return 0;
		await provider.ingest(events);
		this.db
			.transaction(() => {
				for (const event of events)
					this.db
						.query("DELETE FROM outbox WHERE id=? AND ready=1")
						.run(event.eventId);
			})
			.immediate();
		return events.length;
	}
	close(): void {
		this.db.close();
	}
}
