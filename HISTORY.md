# Changelog

## v0.8.0 (2026-07-11)
- **FUSE Mount Improvements**
  - Fixed mount output buffering (messages now display immediately)
  - Fixed Ctrl+C exit handling (single press now works)
  - Implemented proper file decryption and serving via FUSE Read() callback
  
- **Compressed File Support**
  - Added gzip decompression for compressed files in containers
  - Fixed small file reads that appeared as binary garbage
  - Corrected size reporting to distinguish between compressed (StoredSize) and decompressed (Size) file sizes
  
- **Bug Fixes**
  - Fixed race conditions during concurrent FUSE reads with mutex protection
  - Fixed Getattr() to report correct file sizes (Size for compressed, StoredSize for others)
  - Fixed Read() method boundary checks to work with decompressed sizes
  - Corrected file truncation issues when reading compressed files

- **Code Quality**
  - Added thread-safety with Mutex for concurrent file access
  - Improved error handling in FUSE callbacks

## v0.7.4 and earlier
Initial releases with encrypt/decrypt functionality.
