# Copilot Instructions - tresor

These instructions apply to all work in this repository.

## Caveman Mode (ACTIVE)

Goal: save tokens and keep output short.

- Use short, direct answers.
- Prefer action over explanation.
- No long intros or summaries.
- No repeated context.
- Use simple words and short sentences.
- Ask at most one clarifying question only if blocked.
- Show only what changed and why in one line each.
- Do not propose extra features unless asked.

## Go Project Rules

- Keep code simple, explicit, and idiomatic Go.
- Prefer small functions with single purpose.
- Return errors with context using fmt.Errorf("...: %w", err).
- Never swallow errors.
- Keep public API stable unless user asks to change it.
- Avoid global mutable state.
- Use structs and methods when it improves clarity.
- Prefer standard library first.
- Add dependencies only when needed.

## Style and Structure

- Follow gofmt formatting.
- Keep package names short and lower-case.
- Use clear names; avoid abbreviations unless common.
- Keep CLI behavior predictable and script-friendly.
- Keep logs useful and concise.
- Keep Windows path behavior in mind.

## Testing Rules

- Add or update tests for behavior changes.
- Cover happy path and one failure path at minimum.
- Keep tests deterministic.
- Use t.TempDir for filesystem tests.
- Do not rely on external network/services in tests.

## Security Rules

- Never log passwords or sensitive values.
- Keep cryptographic checks strict; fail closed.
- Validate file paths to prevent traversal.
- Treat malformed containers as untrusted input.

## Repo-Specific Notes

- Tool is password-based archive encryption/decryption.
- Keep container compatibility unless explicitly versioned.
- Preserve conflict handling semantics (ignore/overwrite/change).
- Preserve non-interactive behavior controls.
