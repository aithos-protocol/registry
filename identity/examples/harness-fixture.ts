// Integration-only checkout, installed by scripts/prepare-harness.mjs.
import {
	createSalesAgentHarnessApp,
	createSalesAgentHttpHandler,
	parseAgentHarnessConfig,
	SqliteSessionStore,
	type CommerceAdapter,
	type AgentRuntime,
} from "../.fixtures/harness/src/index.js";
import configJson from "../.fixtures/harness/config/agents/demo-sales-agent.json";
import type { Admission } from "../src/admission.js";

export function makeHarness(admission: Admission, databasePath: string) {
	const calls = { runtime: 0, catalog: 0, cart: 0, payment: 0 };
	const config = parseAgentHarnessConfig({
		...configJson,
		merchantId: "shop",
		policies: { ...configJson.policies, allowCheckoutCompletion: false },
	});
	const cart = {
		cartId: "test-cart",
		items: [],
		subtotal: { amount: 0, currency: "EUR" },
		total: { amount: 0, currency: "EUR" },
		currency: "EUR",
	};
	const adapter: CommerceAdapter = {
		searchProducts: async () => {
			calls.catalog++;
			return { products: [], dataSource: "shopware_store_api" };
		},
		getProductDetails: async () => {
			calls.catalog++;
			return {
				product: {
					id: "test-product",
					label: "Synthetic jacket",
					categories: [],
					attributes: {},
					variants: [],
				},
				dataSource: "shopware_store_api",
			};
		},
		createCart: async () => {
			calls.cart++;
			return { cart, dataSource: "shopware_store_api" };
		},
		updateCart: async () => {
			calls.cart++;
			return { cart, dataSource: "shopware_store_api" };
		},
		getCartSummary: async () => ({ cart, dataSource: "shopware_store_api" }),
		prepareCheckoutHandoff: async () => {
			throw new Error("Handoff disabled in identity demo");
		},
		completeCheckout: async () => {
			calls.payment++;
			throw new Error("Payments disabled");
		},
	};
	const store = new SqliteSessionStore({ databasePath });
	const app = createSalesAgentHarnessApp({
		config,
		adapter,
		sessionStore: store,
		callerAccess: admission,
		runtimeFactory: ({ tools }) => {
			const respond: AgentRuntime["respond"] = async (input) => {
				calls.runtime++;
				// Simulate an untrusted model picking a tool; the harness enforces policy.
				const capability =
					input.message === "attempt-cart" ? "createCart" : "searchProducts";
				const tool = tools.find((t) => t.name === capability)!;
				await tool.execute(
					capability === "createCart"
						? { items: [{ productId: "test-product", quantity: 1 }] }
						: { query: "jacket" },
					{ agentSessionId: input.agentSessionId },
				);
				return {
					message: "Synthetic catalogue response",
					toolCalls: [capability],
				};
			};
			return {
				respond,
				startRun: async () => {
					throw new Error("Unused in synchronous harness demo");
				},
				resumeRun: async () => {
					throw new Error("Unused in synchronous harness demo");
				},
				getRun: () => undefined,
				cancelRun: () => undefined,
			};
		},
	});
	return {
		app,
		store,
		calls,
		handler: createSalesAgentHttpHandler({
			app,
			agentConfig: config,
			admission,
		}),
	};
}
