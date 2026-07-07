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

## Release

This project uses GoReleaser and a GitHub Actions workflow.

- Configuration: `.goreleaser.yaml`
- Workflow: `.github/workflows/release.yml`
- Trigger: push a tag like `v0.1.0`

Create and push a release tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Optional local dry run:

```bash
goreleaser release --snapshot --clean
```
