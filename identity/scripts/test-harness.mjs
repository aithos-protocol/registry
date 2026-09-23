import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cwd = fileURLToPath(new URL("../.fixtures/harness/", import.meta.url));
const files = execFileSync("git", ["ls-files", "--", "tests"], {
	cwd,
	encoding: "utf8",
})
	.trim()
	.split("\n")
	.filter((path) => path.endsWith(".test.ts"))
	.sort();
if (!files.length) throw new Error("Partner test files are missing");
// Upstream caches a module-level tracer across trace.disable()/provider resets.
// Reproduces unpatched with bootstrap -> langfuse-tracing -> langgraph-runtime.
// A fresh process per file isolates global instrumentation without skipping any
// test, changing any assertion, or altering the partner's production runtime.
for (const file of files)
	execFileSync("bun", ["test", `./${file}`], { cwd, stdio: "inherit" });
console.log(
	`All ${files.length} partner test files passed in isolated processes.`,
);
