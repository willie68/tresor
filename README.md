# tresor
Simple file tresor for en/decrypting different folders into one file.

Small command-line tool for encrypting and decrypting directory trees into a `.tre` container file.

## Commands (stub)

Encrypt:

```bash
tresor encrypt --password <mein-passwort> --remove --file e:\temp\meintresor.tre mongodump\ minio\
```

Decrypt:

```bash
tresor decrypt --password <mein-passwort> --remove --file e:\temp\meintresor.tre
```

Current state: CLI and flag parsing are implemented as stubs. Encryption/decryption functionality is not implemented yet.
