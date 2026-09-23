import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const fixtures = join(root, ".fixtures");
const target = join(fixtures, "harness");
const patchPath = join(root, "partner", "sales-agent-harness.patch");
const base = "51efcee7d7680f8e3fe8444a4dbed029129caf94";
const source =
	process.argv[2] ??
	"https://github.com/agentic-commerce-lab/sales-agent-harness.git";
const hash = (data) => createHash("sha256").update(data).digest("hex");
const run = (binary, args, cwd = root) =>
	execFileSync(binary, args, { cwd, stdio: "inherit" });
mkdirSync(fixtures, { recursive: true });
if (!existsSync(target)) {
	run("git", ["clone", "--no-hardlinks", "--no-checkout", source, target]);
	run("git", ["checkout", "--detach", base], target);
	run("git", ["apply", "--check", patchPath], target);
	run("git", ["apply", "--index", patchPath], target);
}
// Never reset or overwrite a pre-existing checkout; refuse unexpected changes.
const head = execFileSync("git", ["rev-parse", "HEAD"], {
	cwd: target,
	encoding: "utf8",
}).trim();
const staged = execFileSync("git", ["diff", "--cached", "--binary", base], {
	cwd: target,
});
if (head !== base || hash(staged) !== hash(readFileSync(patchPath)))
	throw new Error(
		"Fixture differs from the pinned proposal; refusing to overwrite it",
	);
run("git", ["diff", "--exit-code"], target);
run("bun", ["install", "--frozen-lockfile", "--ignore-scripts"], target);
console.log(
	`Harness ready at ${target}; upstream ${base}; patch SHA256 ${hash(staged)}`,
);
