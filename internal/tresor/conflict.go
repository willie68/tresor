package tresor

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func normalizeInputRoots(inputs []string) ([]string, error) {
	roots := make([]string, 0, len(inputs))
	seen := make(map[string]struct{})
	for _, in := range inputs {
		if strings.TrimSpace(in) == "" {
			continue
		}
		absPath, err := filepath.Abs(in)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(absPath); err != nil {
			return nil, fmt.Errorf("stat input %q: %w", in, err)
		}
		if _, ok := seen[absPath]; ok {
			continue
		}
		seen[absPath] = struct{}{}
		roots = append(roots, absPath)
	}
	if len(roots) == 0 {
		return nil, errors.New("no valid input paths provided")
	}
	return roots, nil
}

func safeOutputPath(storedPath string) (string, error) {
	if strings.TrimSpace(storedPath) == "" {
		return "", errors.New("invalid empty path in container")
	}
	target := filepath.FromSlash(storedPath)
	if filepath.IsAbs(target) {
		return "", fmt.Errorf("invalid absolute path in container: %q", storedPath)
	}
	clean := filepath.Clean(target)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid path traversal in container: %q", storedPath)
	}
	return clean, nil
}

func resolveFileConflictTarget(target string, handler FileConflictHandler) (resolved string, skip bool, err error) {
	if _, statErr := os.Stat(target); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return target, false, nil
		}
		return "", false, fmt.Errorf("check target %q: %w", target, statErr)
	}

	if handler == nil {
		handler = promptFileConflict
	}

	action, err := handler(target)
	if err != nil {
		return "", false, err
	}

	switch action {
	case ConflictIgnore:
		return "", true, nil
	case ConflictOverwrite:
		info, err := os.Stat(target)
		if err != nil {
			return "", false, fmt.Errorf("stat existing target %q: %w", target, err)
		}
		if info.IsDir() {
			return "", false, fmt.Errorf("cannot overwrite directory with file: %q", target)
		}
		return target, false, nil
	case ConflictRename:
		resolvedTarget, skip, err := nextAvailableRenamedName(target)
		if err != nil {
			return "", false, err
		}
		fmt.Fprintf(os.Stderr, "conflict rename: %q -> %q\n", target, resolvedTarget)
		return resolvedTarget, skip, nil
	default:
		return "", false, fmt.Errorf("unknown conflict action for %q", target)
	}
}

func promptFileConflict(target string) (FileConflictAction, error) {
	if !isInteractiveTerminal() {
		return 0, fmt.Errorf("target file exists %q and no interactive terminal is available", target)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr, "file %q already exists. [i]gnore/[o]verwrite/[r]ename: ", target)
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("read conflict choice: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "i", "ignore":
			return ConflictIgnore, nil
		case "o", "overwrite":
			return ConflictOverwrite, nil
		case "r", "rename", "c", "change":
			return ConflictRename, nil
		default:
			fmt.Fprintln(os.Stderr, "please enter i, o, or r")
		}
	}
}

func nextAvailableRenamedName(target string) (string, bool, error) {
	dir := filepath.Dir(target)
	base := filepath.Base(target)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	for i := 1; ; i++ {
		candidateBase := fmt.Sprintf("%s (%04d)%s", name, i, ext)
		candidate := filepath.Join(dir, candidateBase)
		_, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			return candidate, false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("check candidate path %q: %w", candidate, err)
		}
	}
}

func isInteractiveTerminal() bool {
	stdinInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	stdoutInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stdinInfo.Mode()&os.ModeCharDevice) != 0 && (stdoutInfo.Mode()&os.ModeCharDevice) != 0
}

func nextArchiveRenamedPath(targetPath string, existing map[string]int) string {
	dir := path.Dir(targetPath)
	base := path.Base(targetPath)
	ext := path.Ext(base)
	name := strings.TrimSuffix(base, ext)
	for i := 1; ; i++ {
		candidateBase := fmt.Sprintf("%s (%04d)%s", name, i, ext)
		candidate := candidateBase
		if dir != "." {
			candidate = dir + "/" + candidateBase
		}
		if _, ok := existing[candidate]; !ok {
			return candidate
		}
	}
}
