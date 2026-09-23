import { parseDictionary, type Dictionary } from "structured-headers";
import { fail } from "./contracts.js";

// The maintained library owns grammar/serialization. This lexical pass retains
// duplicate names before its Map parser could discard them (same approach as
// agent-request-auth/python/_structured.py). It does not parse SF values.
export function strictDictionary(input: string): Dictionary {
	const members: string[] = [];
	let start = 0,
		depth = 0,
		quoted = false,
		escaped = false;
	let parameters = new Set<string>();
	for (let i = 0; i < input.length; i++) {
		const c = input[i];
		if (quoted) {
			if (escaped) escaped = false;
			else if (c === "\\") escaped = true;
			else if (c === '"') quoted = false;
			continue;
		}
		if (c === '"') {
			quoted = true;
			continue;
		}
		if (c === "(") depth++;
		if (c === ")") depth--;
		if (c === ";" && depth === 0) {
			const name = /^; *([a-z*][a-z0-9_.*-]*)/.exec(input.slice(i))?.[1];
			if (!name || parameters.has(name)) fail(401, "invalid_proof");
			parameters.add(name);
		}
		if (c === "," && depth === 0) {
			members.push(input.slice(start, i).trim());
			start = i + 1;
			parameters = new Set();
		}
	}
	members.push(input.slice(start).trim());
	const names = members.map((m) => /^([a-z*][a-z0-9_.*-]*)/.exec(m)?.[1]);
	if (names.some((n) => !n) || new Set(names).size !== names.length)
		fail(401, "invalid_proof");
	try {
		return parseDictionary(input);
	} catch {
		return fail(401, "invalid_proof");
	}
}
