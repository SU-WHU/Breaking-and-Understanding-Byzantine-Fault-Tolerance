### See Detailed Report:

```
    bft-lab/
    |__ Workshop 2 Part 1-4.md  # pt 1-4
    |__ Workshop2_Part5-7.md    # pt 5-7
    |__ PART8_README.md         # pt 8 --> also points to Part8_Hardening_Report.md
```

### Part 7:

Open a terminal in directory `scenarios/`, then run:

```
node bft_break_p7.js
```

### Part 8:

Open a terminal in this directory, then run:
```
npm test
npm run part8
npm run verify-certificate
```

- npm run part8 runs all five demonstrations and saves JSON evidence. 
- npm run verify-certificate independently checks the saved certificate against the public keys and quorum in evidence/trusted-config.json.
- The verifier must obtain that configuration from a trusted administrator.

To regenerate all execution logs and the validation summary:

```
npm run validate
```
