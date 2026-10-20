console.log("Available scenarios and checks:");
for (const name of ["honest", "byzantine", "equivocation", "key-theft", "sybil", "quorum", "certificates", "part8", "verify-certificate", "test"]) {
    console.log(`npm run ${name}`);
}
