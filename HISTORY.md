# Changelog

## v0.15.1 (2026-08-26)
- GoReleaser config: replace deprecated `archives.builds` / `format_overrides.format` with `ids` / `formats`

## v0.15.0 (2026-08-25)
- Encrypt: compress files up to 32 MiB in memory; skip gzip early when it does not shrink the payload
- Remove unused read-write / in-memory FUSE filesystem experiment (`MemoryFS`, `internal/memfs`)
- Mount remains read-only only
- Local build script sets `CGO_ENABLED=0` to match GoReleaser / WinFSP pure-Go path

## v0.14.1 (2026-07-19)
- Update `gowillie68` dependency and remove local `replace` directive

## v0.14.0 (2026-07-19)
- Add `--secure-remove` for encrypt: Gutmann-method secure deletion (3 passes); requires `--remove`

## v0.13.0 (2026-07-16)
- **Enhanced Wildcard Filter Support**
  - Extended filter patterns to support generic glob wildcards (e.g., `rep*`, `file*.txt`)
  - Wildcard patterns now use filepath.Match() for standard glob matching
  - Examples: `tresor list --filter "rep*"` finds `replace_0000.jpg`, `report.pdf`, etc.
  - Wildcard patterns match against filename only (not full path)

## v0.12.0 (2026-07-15)
- **Filter Support for List Command**
  - Added `-filter` flag for listing container contents with pattern matching
  - Supports filter types: extension (`.jpg`), wildcard (`*.jpg`), substring (`secrets`), directory (`secrets/`), root directory (`/secrets/`), exact filename (`readme.pdf`)
  - All filters are case-insensitive
  - Examples: `tresor list --filter ".jpg"` or `tresor list --filter "secrets/"`

- **Short Flag Aliases**
  - Added short flag variants for common options:
    - `-p` (short for `--password`)
    - `-f` (short for `--file`)
    - `-r` (short for `--remove`)
    - `-h` (short for `--help`)
  - Available across all commands: encrypt, decrypt, list, extract, mount
  - Example: `tresor list -p mypass -f secretsfile.tre --filter ".jpg"`

- **Documentation Updates**
  - Updated README with global flags section and short flag examples
  - Added comprehensive filter pattern documentation with examples

## v0.11.0 (2026-07-15)
- Multi-container support via `--max-size` (main `.tre` plus sidecar containers)
- Mount fixes related to multi-container reading

## v0.10.0 (2026-07-14)
- File cache implementation: configurable in-memory cache for FUSE filesystem with LRU eviction
- Mount cache parameter: new `--cache-size` flag (in MB) for optional file caching
- Cache tests covering normal operations, edge cases, and eviction behavior
- Filesystem cache integration: ReadOnlyFS supports optional caching for improved performance

## v0.9.0 (2026-07-13)
- Windows-only mount command with Unix stub for cross-platform builds
- Volume mount improvements: volume name and capacity reporting

## v0.8.3 (2026-07-11)
- Improve FUSE mount reliability and file reading
- Document FUSE / WinFSP requirements in README

## v0.8.2 (2026-07-11)
- Fix file type constants: use `entryTypeFile` / `entryTypeDir` consistently

## v0.8.1
- New `mount` command: mount tresor container as read-only FUSE filesystem
- Fixed mount output buffering: messages now display immediately
- Fixed Ctrl+C exit handling: single press properly unmounts and exits
- Implemented proper FUSE `Read()` callback with full file decryption
- Compressed file support: gzip decompression for transparent access
- Fixed small file read corruption and file truncation for decompressed sizes
- Thread-safety improvements: mutex protection for concurrent FUSE reads

## v0.8.0 (2026-07-11)
- **FUSE Mount Improvements**
  - Fixed mount output buffering
  - Fixed Ctrl+C exit handling
  - Implemented proper file decryption and serving via FUSE `Read()` callback

- **Compressed File Support**
  - Added gzip decompression for compressed files in containers
  - Fixed small file reads that appeared as binary garbage
  - Corrected size reporting to distinguish between compressed (`StoredSize`) and decompressed (`Size`) file sizes

- **Bug Fixes**
  - Fixed race conditions during concurrent FUSE reads with mutex protection
  - Fixed `Getattr()` / `Read()` size handling for compressed files

## v0.7.4
- Platform-specific `list` output: Windows PowerShell-style dir format, Linux/Unix and macOS `ls -l` style

## v0.7.3
- Improved `list` output to PowerShell-style table (Mode, LastWriteTime, Length, Name)

## v0.7.2
- Security documentation: brute-force resistance analysis for Argon2id KDF
- Brute-force test (`TestBruteForceResistance`): weak passwords fail; ~100-500ms per attempt

## v0.7.1
- Single source of truth for version number via ldflags from git tag
- Modification times in `list` (`YYYY-MM-DD HH:MM:SS`)
- New `extract` command for selective extraction (`--force-dirs` optional)
- Optional `--file` flag across commands (defaults to `tresor.tre`)
- Early validation of container file and flags before password prompt
- Interactive password input as default (`--password` only for automation)

## v0.5.0
- #3: ModTime preservation in encrypt/decrypt round trip (**non-backward-compatible**: old containers lack ModTime)

## v0.4.0
- #1: Progress output for encrypt and decrypt
- #2: Summary output for `list` (files, dirs, total bytes)

## Earlier
Initial releases with encrypt/decrypt functionality.
