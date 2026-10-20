const fs = require("node:fs");
const path = require("node:path");
const ValidatorRegistry = require("./registry");
const { verifyCertificate } = require("./certificate");

try {
    const certificatePath = process.argv[2] || path.join(__dirname, "evidence", "commit-certificate.json");
    const configPath = process.argv[3] || path.join(__dirname, "evidence", "trusted-config.json");
    const certificate = JSON.parse(fs.readFileSync(certificatePath, "utf8"));
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const registry = new ValidatorRegistry(config.validators);
    const result = verifyCertificate(certificate, registry, config.quorum);
    console.log(JSON.stringify(result, null, 2));
    if (!result.valid) process.exitCode = 1;
} catch (error) {
    console.error(`Certificate verification failed: ${error.message}`);
    process.exitCode = 1;
}
