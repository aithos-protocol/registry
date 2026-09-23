import { z } from "zod";
import { IdentityError, PROFILE } from "./contracts.js";

export class ExtensionRequired extends IdentityError {
	constructor(readonly body: Uint8Array) {
		super(400, "extension_required");
	}
}
/** Serializes only our extension-negotiation error; the harness owns A2A. */
export function extensionResponse(path: string, body: Uint8Array): Response {
	const message =
		"Activate the required agent-request-auth extension before signing.";
	const headers = { "cache-control": "no-store" };
	if (path === "/") {
		let id: string | number | null = null;
		try {
			const input = z
				.object({ id: z.union([z.string(), z.number(), z.null()]) })
				.safeParse(JSON.parse(Buffer.from(body).toString()));
			if (input.success) id = input.data.id;
		} catch {
			/* Invalid JSON has no recoverable RPC id. */
		}
		return Response.json(
			{
				jsonrpc: "2.0",
				id,
				error: {
					code: -32008,
					message,
					data: { requiredExtensions: [PROFILE] },
				},
			},
			{ status: 400, headers },
		);
	}
	return Response.json(
		{
			type: "https://a2a-protocol.org/errors/extension-support-required",
			title: "Extension Support Required",
			status: 400,
			detail: message,
			requiredExtensions: [PROFILE],
		},
		{
			status: 400,
			headers: { ...headers, "content-type": "application/problem+json" },
		},
	);
}
