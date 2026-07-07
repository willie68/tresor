# tresor
Simple file tresor for en/decrypting different folders into one file.

Small command-line tool for encrypting and decrypting directory trees into a `.tre` container file.

## Commands

Encrypt:

```bash
tresor encrypt --password <mein-passwort> --remove --file e:\temp\meintresor.tre mongodump\ minio\
```

If the target container already exists, use `--if-exists`:

```bash
tresor encrypt --file e:\temp\meintresor.tre --if-exists sync mongodump\ minio\
tresor encrypt --file e:\temp\meintresor.tre --if-exists append mongodump\ minio\
```

- `sync`: resulting container reflects the current input folders
- `append`: add new files to existing container

For append conflicts, use `--on-conflict` (also for non-interactive runs):

```bash
tresor encrypt --file e:\temp\meintresor.tre --if-exists append --on-conflict ignore mongodump\
tresor encrypt --file e:\temp\meintresor.tre --if-exists append --on-conflict overwrite mongodump\
tresor encrypt --file e:\temp\meintresor.tre --if-exists append --on-conflict change mongodump\
```

Decrypt:

```bash
tresor decrypt --password <mein-passwort> --remove --file e:\temp\meintresor.tre
```

If files already exist during decrypt, use `--on-conflict` to define behavior:

```bash
tresor decrypt --file e:\temp\meintresor.tre --on-conflict ignore
tresor decrypt --file e:\temp\meintresor.tre --on-conflict overwrite
tresor decrypt --file e:\temp\meintresor.tre --on-conflict change
```

Default is `--on-conflict prompt`.

List:

```bash
tresor list --password <mein-passwort> --file e:\temp\meintresor.tre
```

This prints a `dir`-like listing with full output paths.

Current state: recursive encryption/decryption is implemented for regular files and directories.

## Container Format (v1)

- Password-based key derivation: Argon2id
- Content encryption: AES-256-GCM
- Optional per-file compression (gzip) before encryption, only when it reduces size
- All file and directory metadata (including names, sizes, offsets) is stored only inside an encrypted index
- File payload is encrypted in fixed-size chunks (64 KiB plaintext -> 64 KiB + GCM tag ciphertext per chunk)

Container layout:

1. Binary header (version, KDF params, salt)
2. Encrypted file chunks (no plaintext file content)
3. Encrypted index (contains file paths, modes, sizes, chunk metadata)
4. Binary footer (index location and nonce)

This means no readable filenames or file content appear in plaintext inside the container.

## Local Build

Run the local build script from the repository root:

```powershell
./scripts/build-local.ps1
```

This script runs `go mod tidy`, `go test ./...`, and builds `bin/tresor.exe`.

## Debug In VS Code

Debug configurations are available in `.vscode/launch.json`:

- `tresor: encrypt`
- `tresor: decrypt`

Included sample data:

- `testdata/input/mongodump/dump-001.bson`
- `testdata/input/minio/bucket-a/object-001.txt`

The encrypt debug config writes `testdata/vault.tre`. The decrypt debug config restores files into `testdata/output`.

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
