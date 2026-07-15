# tresor
Small command-line tool for encrypting and decrypting directory trees into a `.tre` container file.

Current release: `v0.12.0`

## Commands

### Global Flags

Common flags available across all commands:
- `-p, --password`: Password for encryption/decryption
- `-f, --file`: Container file path (`.tre`)
- `-r, --remove`: Remove source/container file after successful operation
- `-h, --help`: Show help information

### Encrypt

```bash
tresor encrypt --remove mongodump\ minio\
tresor encrypt --file e:\temp\meintresor.tre mongodump\ minio\
tresor encrypt -p mypass -f archive.tre -r mongodump\ minio\  # Using short flags
```

If `--file` is omitted, `tresor.tre` in the current directory is used.

**Options:**

- `-r, --remove`: Remove source files after successful encryption (useful for cleanup after creating the container)
- `--if-exists`: Define behavior when target container already exists (see below)
- `--on-conflict`: Define conflict handling during append operations (see below)

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
tresor encrypt -p <mein-passwort> -r mongodump\ minio\  # Using short flags
```

#### Multi-Container Encryption

For large archives, you can split data across multiple container files using `--max-size`:

```bash
tresor encrypt --max-size 100 --remove mongodump\ minio\
tresor encrypt --file archive.tre --max-size 500 mongodump\
```

**How it works:**

- `--max-size`: Maximum target size for each container file in MB (default: 0 = unlimited, all data in single file)
- When specified, creates a main container (`archive.tre`) plus sidecar files (`archive.tre.000`, `archive.tre.001`, etc.)
- Each complete file is written to a single container - **files never split across containers**
- Container switching happens between files: if the next file won't fit, encrypt switches to a new container
- **Important:** Individual files larger than `--max-size` are always written completely to their container (containers may exceed the size limit to keep files intact)
- The index is always stored in the main container file only

**Example with --max-size 100 (MB):**

```
file1.bin (80 MB) → Container 0 (main)        [80 MB]
file2.bin (80 MB) → Container 1 (.000)        [80 MB] 
file3.bin (30 MB) → Container 1 (.000)        [110 MB - exceeds limit but keeps file intact]
file4.bin (50 MB) → Container 2 (.001)        [50 MB]
```

**Benefits:**

- Store large archives on size-limited media (USB drives, cloud storage with file limits)
- Easier transport of very large encrypted data
- Container files are independent and can be lost without affecting main file integrity

**Decryption:**

Multi-container archives decrypt transparently - just point to the main `.tre` file and all sidecar containers are automatically detected and read:

```bash
tresor decrypt --file archive.tre    # Automatically reads archive.tre.000, archive.tre.001, etc.
```

### Decrypt

```bash
tresor decrypt --remove
tresor decrypt --file e:\temp\meintresor.tre
```

If `--file` is omitted, `tresor.tre` in the current directory is used.

**Options:**

- `--remove`: Remove the container file after successful decryption (useful if you no longer need the encrypted file after extracting)
- `--on-conflict`: Define behavior if files already exist during decrypt (see below)

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
tresor list --filter ".jpg"              # All JPG files (case-insensitive)
tresor list --filter "input/"            # Files in input directory and subdirectories
tresor list --filter "/input/"           # Files directly in root input directory
```

**Filter patterns** (case-insensitive):

| Pattern | Matches | Examples |
|---------|---------|----------|
| `.jpg` | Files with extension `.jpg` | `photo.jpg`, `image.JPG`, `pic.jPg` |
| `*.jpg` | Files ending with `.jpg` (wildcard) | `photo.jpg`, `image.JPG` |
| `input` | Files containing "input" anywhere | `input`, `input/file.txt`, `my_input_file.pdf` |
| `input/` | Files in directory (including subdirs) | `input/config.ini`, `input/nested/file.txt` |
| `/input/` | Files directly in root directory only | `input/config.ini`, but NOT `input/nested/file.txt` |
| `readme.pdf` | Exact filename (any location) | `readme.pdf`, `docs/readme.pdf` |

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

### Mount

```bash
tresor mount x:
tresor mount y: --file e:\temp\meintresor.tre
tresor mount z: --cache-size 100              # With 100 MB file cache
```

Mount a tresor container as a read-only filesystem using FUSE (Filesystem in Userspace).

**Supported platforms:**
- **Windows only** (requires WinFSP)

**Requirements:**

- **Windows**: [WinFSP](https://github.com/winfsp/winfsp/releases) must be installed

**Options:**

- `--file`: Container file path (defaults to `tresor.tre`)
- `--cache-size`: File cache size in MB (defaults to 0 = no cache)
  - Speeds up repeated file access by caching decrypted data in memory
  - Useful for containers with frequently accessed files
  - Example: `--cache-size 100` uses up to 100 MB RAM for caching

Features:
- Read-only access to all files and directories in the container
- Transparent decompression of compressed files
- Full file path and metadata support
- Real-time access without extracting (files remain in encrypted container)
- Optional in-memory file cache for improved performance

Example:
```bash
# Mount container to drive x:
tresor mount x:

# Navigate and read files
dir x:\\                    # List container contents
type x:\\input\\file.txt    # Read a specific file

# Unmount by pressing Ctrl+C
```

If `--file` is omitted, `tresor.tre` in the current directory is used.

### Password Handling

The `--password` flag is optional. If omitted, you will be prompted to enter the password interactively. Use `--password` only for automated scenarios (scripts, CI/CD pipelines).

### Version

```bash
tresor version
```

Shows version, a short about text, and a license hint.

## Resolved Issues In v0.10.0

- File cache implementation: Added configurable in-memory cache for FUSE filesystem with LRU eviction
- Mount cache parameter: New `--cache-size` flag (in MB) for optional file caching
- Cache tests: Comprehensive test suite covering normal operations, edge cases, and eviction behavior
- Filesystem cache integration: ReadOnlyFS now supports optional caching for improved performance

## Resolved Issues In v0.8.1

- New `mount` command: Mount tresor container as read-only FUSE filesystem for transparent file access
- Fixed mount output buffering: Messages now display immediately (not deferred)
- Fixed Ctrl+C exit handling: Single press now properly unmounts and exits
- Implemented proper FUSE Read() callback: Full file decryption and serving via filesystem
- Compressed file support: Added gzip decompression for transparent access to compressed files
- Fixed small file read corruption: Binary garbage now properly decrypts and decompresses
- Fixed file truncation: Read() now correctly handles decompressed vs. stored file sizes
- Thread-safety improvements: Mutex protection for concurrent FUSE reads

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
