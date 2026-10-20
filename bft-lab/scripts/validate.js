const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const directory = path.join(root, "evidence");
fs.mkdirSync(directory, { recursive: true });
const runs = [
    ["unit-tests.tap", ["--test", "--test-reporter=tap", "test/part8.test.js"]],
    ["part8-demo.txt", ["scenarios/part8.js"]],
    ["certificate-verification.txt", ["verify-certificate.js"]],
    ["honest.txt", ["scenarios/honest.js"]],
    ["byzantine.txt", ["scenarios/byzantine.js"]],
    ["equivocation.txt", ["scenarios/equivocation.js"]],
    ["key-theft.txt", ["scenarios/key_theft.js"]],
    ["sybil.txt", ["scenarios/sybil.js"]],
    ["quorum.txt", ["scenarios/quorum_tampering.js"]],
    ["certificates.txt", ["scenarios/commit_certificate.js"]],
    ["available-commands.txt", ["index.js"]]
];

const results = [];
for (const [filename, args] of runs) {
    const run = spawnSync(process.execPath, args, { cwd: root, encoding: "utf8" });
    if (run.error) throw run.error;
    fs.writeFileSync(path.join(directory, filename), run.stdout + run.stderr);
    results.push({ command: `node ${args.join(" ")}`, exitCode: run.status, evidence: filename });
    console.log(`${run.status === 0 ? "PASS" : "FAIL"}: node ${args.join(" ")}`);
}
const tap = fs.readFileSync(path.join(directory, "unit-tests.tap"), "utf8");
const summary = {
    generatedAt: new Date().toISOString(),
    nodeVersion: process.version,
    tests: Number(tap.match(/^# tests (\d+)$/m)?.[1]),
    passed: Number(tap.match(/^# pass (\d+)$/m)?.[1]),
    failed: Number(tap.match(/^# fail (\d+)$/m)?.[1]),
    runs: results
};
fs.writeFileSync(path.join(directory, "validation-summary.json"), JSON.stringify(summary, null, 2) + "\n");
if (results.some(result => result.exitCode !== 0) || !summary.tests || summary.failed) {
    process.exitCode = 1;
} else {
    console.log(`Validated ${summary.tests} tests and ${runs.length - 1} other commands.`);
}
