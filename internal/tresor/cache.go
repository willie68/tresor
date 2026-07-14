package tresor

import "time"

// this is a configurable Filecache implementation that can be used to cache decrypted files in memory or on disk. It is used to speed up access to frequently accessed files and reduce the number of decryption operations.

type cacheEntry struct {
	data     []byte
	size     int64
	created  time.Time
	accessed time.Time
}

type FileCache struct {
	cache   map[string]*cacheEntry
	maxSize int64 // maximum size of the cache in bytes
	size    int64 // total size of all cached files
	active  bool  // indicates if the cache is active
}

func NewFileCache(maxSize int64) *FileCache {
	active := true
	if maxSize <= 0 {
		active = false
	}
	return &FileCache{
		cache:   make(map[string]*cacheEntry),
		maxSize: maxSize,
		active:  active,
	}
}

func (fc *FileCache) Has(path string) bool {
	if !fc.active {
		return false
	}
	_, exists := fc.cache[path]
	return exists
}

func (fc *FileCache) Get(path string) ([]byte, bool) {
	if !fc.active {
		return nil, false
	}
	entry, exists := fc.cache[path]
	if !exists {
		return nil, false
	}
	entry.accessed = time.Now()
	return entry.data, true
}

func (fc *FileCache) Set(path string, data []byte) {
	if !fc.active {
		return
	}
	fc.cache[path] = &cacheEntry{
		data:     data,
		size:     int64(len(data)),
		created:  time.Now(),
		accessed: time.Now(),
	}
	fc.recalculateSize()
	if fc.maxSize > 0 && fc.size > fc.maxSize {
		fc.evict()
	}
}

func (fc *FileCache) Delete(path string) {
	if !fc.active {
		return
	}
	delete(fc.cache, path)
	fc.recalculateSize()
}

func (fc *FileCache) Clear() {
	if !fc.active {
		return
	}
	fc.cache = make(map[string]*cacheEntry)
	fc.size = 0
}

func (fc *FileCache) Size() int64 {
	return fc.size
}

func (fc *FileCache) recalculateSize() {
	if !fc.active {
		return
	}
	var totalSize int64
	for _, entry := range fc.cache {
		totalSize += entry.size
	}
	fc.size = totalSize
}

func (fc *FileCache) evict() {
	if !fc.active {
		return
	}
	// Evict least recently accessed entries until the cache size is below the maximum size
	for fc.size > fc.maxSize {
		// Find the least recently accessed entry
		var oldestKey string
		var oldestAccess time.Time
		for key, entry := range fc.cache {
			if oldestKey == "" || entry.accessed.Before(oldestAccess) {
				oldestKey = key
				oldestAccess = entry.accessed
			}
		}
		if oldestKey == "" {
			break
		}
		delete(fc.cache, oldestKey)
		fc.recalculateSize()
	}
}
