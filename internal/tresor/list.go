package tresor

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
)

func matchesFilter(path string, filter string) bool {
	if filter == "" {
		return true
	}

	lowerPath := strings.ToLower(path)
	lowerFilter := strings.ToLower(filter)

	// Normalize path separators to forward slash for consistency
	lowerPath = strings.ReplaceAll(lowerPath, "\\", "/")
	lowerFilter = strings.ReplaceAll(lowerFilter, "\\", "/")

	// Case 1: Extension only (e.g., ".jpg")
	if strings.HasPrefix(lowerFilter, ".") && !strings.Contains(lowerFilter[1:], ".") && !strings.Contains(lowerFilter, "/") {
		return strings.HasSuffix(lowerPath, lowerFilter)
	}

	// Case 2: Wildcard pattern (e.g., "*.jpg", "rep*", "file*.txt")
	if strings.Contains(lowerFilter, "*") && !strings.Contains(lowerFilter, "/") {
		// Match against the filename only for patterns without path separator
		filename := filepath.Base(lowerPath)
		ok, err := filepath.Match(lowerFilter, filename)
		return err == nil && ok
	}

	// Case 3: Root directory (e.g., "\input\\" or "/input/")
	if strings.HasPrefix(lowerFilter, "/") && strings.HasSuffix(lowerFilter, "/") {
		dir := strings.Trim(lowerFilter, "/")
		// Match files directly in this root directory (no further nesting)
		parts := strings.Split(lowerPath, "/")
		if len(parts) == 2 && parts[0] == dir {
			return true
		}
		return false
	}

	// Case 4: Subdirectory (e.g., "input/" or "input/")
	if strings.HasSuffix(lowerFilter, "/") {
		dir := strings.TrimSuffix(lowerFilter, "/")
		// Match files in this directory or subdirectories
		return strings.HasPrefix(lowerPath, dir+"/")
	}

	// Case 5: Full path match (contains slash in filter)
	if strings.Contains(lowerFilter, "/") {
		// Must match the full path exactly or as substring with proper boundaries
		return lowerPath == lowerFilter || strings.Contains(lowerPath, "/"+lowerFilter)
	}

	// Default: substring or filename match
	// If filter looks like a filename (contains dot), only match as exact path or with slash prefix
	// Otherwise match anywhere as substring
	if strings.Contains(lowerFilter, ".") && !strings.Contains(lowerFilter, "/") {
		// Likely a filename - match only exact or with slash prefix
		return lowerPath == lowerFilter || strings.Contains(lowerPath, "/"+lowerFilter)
	}

	// Generic substring match (for names like "input" without dots)
	return strings.Contains(lowerPath, lowerFilter)
}

func List(opts ListOptions) ([]ListedEntry, error) {
	if opts.Password == "" {
		return nil, errors.New("password is required")
	}
	if opts.ContainerPath == "" {
		return nil, errors.New("container file is required")
	}

	_, index, _, err := readContainerIndex(opts.ContainerPath, opts.Password)
	if err != nil {
		return nil, err
	}

	entries := make([]ListedEntry, 0, len(index.Entries))
	for _, entry := range index.Entries {
		listed := ListedEntry{
			Path:    entry.Path,
			IsDir:   entry.Type == entryTypeDir,
			Size:    entry.Size,
			ModTime: entry.ModTime,
		}
		// Apply filter if specified
		if opts.Filter == "" || matchesFilter(entry.Path, opts.Filter) {
			entries = append(entries, listed)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Path) < strings.ToLower(entries[j].Path)
	})

	return entries, nil
}
