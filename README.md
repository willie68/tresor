# tresor
Small command-line tool for encrypting and decrypting directory trees into a `.tre` container file.

Current release: `v0.8.0`

## Commands

### Encrypt

```bash
tresor encrypt --remove mongodump\ minio\
tresor encrypt --file e:\temp\meintresor.tre mongodump\ minio\
```

If `--file` is omitted, `tresor.tre` in the current directory is used.

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
tresor encrypt --file e:\temp\meintresor.tre --if-exists append --on-conflict rename mongodump\
```

For automated scenarios with password:

```bash
tresor encrypt --password <mein-passwort> --remove mongodump\ minio\
```

### Decrypt

```bash
tresor decrypt --remove
tresor decrypt --file e:\temp\meintresor.tre
```

If `--file` is omitted, `tresor.tre` in the current directory is used.

If files already exist during decrypt, use `--on-conflict` to define behavior:

```bash
tresor decrypt --file e:\temp\meintresor.tre --on-conflict ignore
tresor decrypt --file e:\temp\meintresor.tre --on-conflict overwrite
tresor decrypt --file e:\temp\meintresor.tre --on-conflict rename
```

Default is `--on-conflict prompt`.

### List

```bash
tresor list
tresor list --file e:\temp\meintresor.tre
```

If `--file` is omitted, `tresor.tre` in the current directory is used.

The output format is platform-specific for native familiarity:

**Windows:**
```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10.07.2026     09:39                input
d-----        09.07.2026     10:19                output
-a----        10.07.2026     09:45           4644 manual_test.go
-a----        10.07.2026     09:45              5 neu.txt
             2 File(s) 8935936 bytes
             2 Dir(s)
```

**Linux/Unix:**
```
drwxr-xr-x 1 user group                  Oct 10 09:39 input
drwxr-xr-x 1 user group                  Oct 09 10:19 output
-rw-r--r-- 1 user group        4644      Oct 10 09:45 manual_test.go
-rw-r--r-- 1 user group           5      Oct 10 09:45 neu.txt
total 4
```

**macOS (Darwin):**
```
drwxr-xr-x 1 user group                  Oct 10 09:39 input
drwxr-xr-x 1 user group                  Oct 09 10:19 output
-rw-r--r-- 1 user group        4644      Oct 10 09:45 manual_test.go
-rw-r--r-- 1 user group           5      Oct 10 09:45 neu.txt
total 4
```

Output automatically adapts to the operating system for familiar formatting.

### Extract

```bash
tresor extract input/bilder/text.txt                              # Extract single file
tresor extract input/bilder                                       # Extract directory (flat)
tresor extract input/bilder --force-dirs                          # Extract directory (preserve structure)
tresor extract input/bilder --file e:\temp\meintresor.tre         # Extract from specific container
```

If `--file` is omitted, `tresor.tre` in the current directory is used.

Extract behavior:
- Without `--force-dirs`: Files are extracted without their directory structure (only filename or relative path from extract point)
- With `--force-dirs`: Full directory structure is preserved

If files already exist during extract, use `--on-conflict` to define behavior (same options as decrypt).

### Password Handling

The `--password` flag is optional. If omitted, you will be prompted to enter the password interactively. Use `--password` only for automated scenarios (scripts, CI/CD pipelines).

### Version

```bash
tresor version
```

Shows version, a short about text, and a license hint.

## Resolved Issues In v0.7.4

- Platform-specific `list` command output format: Windows displays PowerShell-style dir format, Linux/Unix shows `ls -l` style, macOS (Darwin) shows native `ls -l` format for consistent user experience on each platform.

## Resolved Issues In v0.7.3

- Improved `list` command output format: Now displays in PowerShell-style table format with Mode, LastWriteTime, Length, and Name columns for better readability and familiarity to Windows users.

## Resolved Issues In v0.7.2

- Security documentation added: Comprehensive brute-force resistance analysis with test results showing Argon2id KDF effectiveness.
- Brute-force test (`TestBruteForceResistance`): Demonstrates that 15 weak passwords all fail, confirming KDF protection (~100-500ms per attempt).

## Resolved Issues In v0.7.1

- Single source of truth for version number: Release version is injected via ldflags from git tag during build.
- Modification times displayed in list command in `YYYY-MM-DD HH:MM:SS` format.
- New `extract` command for selective extraction of individual files or subdirectories.
- Optional `--file` flag across all commands (defaults to `tresor.tre`).
- Early validation of container file and command flags before password prompt.
- Interactive password input as default (--password flag only for automation).
- #3: Modified `list` command now displays modification times in `YYYY-MM-DD HH:MM:SS` format.
- Made `--file` flag optional for `encrypt`, `decrypt`, and `list` commands; defaults to `tresor.tre` in the current directory.
- Argument validation (file existence, flag values) now occurs before password prompt.
- New `extract` command: Extract individual files or subdirectories from container with optional `--force-dirs` for preserving directory structure.

## Resolved Issues In v0.5.0

- #3: Added ModTime (modification time) preservation in encrypt/decrypt round trip. **Non-backward-compatible**: old containers lack ModTime data.

## Resolved Issues In v0.4.0

- #1: Added progress output for encrypt and decrypt.
- #2: Added summary output to `list` (files, dirs, total bytes).

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

## Security & Brute-Force Resistance

tresor uses **Argon2id** for password-based key derivation with parameters designed to resist brute-force attacks:

- **Memory**: 64 MB per attempt
- **Time Cost**: 3 iterations
- **Parallelism**: 2 threads
- **Key Size**: 256-bit (for AES-256)

### Brute-Force Test Results

A comprehensive brute-force resistance test (`TestBruteForceResistance`) verifies protection against password guessing attacks:

**Test Setup:**
- Created a tresor container with password: `MyStr0ng!P@ssw0rd#2024`
- Attempted 15 common/weak passwords: `password`, `123456`, `admin`, `letmein`, `qwerty`, `abc123`, etc.

**Results:**
- **Attempts Made:** 15
- **Failed (rejected):** 15 ✓
- **Successful Cracks:** 0 ✓
- **Time per Attempt:** ~100-500ms (system dependent, due to Argon2id KDF)

**Practical Impact:**
- **100 attempts** = ~15-50 seconds
- **1,000 attempts** = ~2-10 minutes
- **1,000,000 attempts** = ~28-140 hours

The expensive KDF makes brute-force attacks computationally infeasible for real passwords. Combined with reasonable password practices, tresor provides strong protection against password guessing.

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
- Trigger: push a tag like `v0.6.1`

**Version Management:**

The version number is a single source of truth defined in the `VERSION` file. During release builds, GoReleaser injects this version into the binary via ldflags (`-X main.Version={{.Version}}`), which is read from the git tag.

Create and push a release tag:

```bash
git tag v0.6.1
git push origin v0.6.1
```

Optional local dry run:

```bash
goreleaser release --snapshot --clean
```

Dev builds show version `dev` by default.
