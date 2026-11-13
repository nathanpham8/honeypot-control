# Repository rules for Claude Code

## Commits and pull requests
- Do not add `Co-Authored-By: Claude`, `Claude-Session:` links, session URLs, or "Generated with Claude Code" footers to commits or PR descriptions.
- Keep the configured git author identity. Never set or change it to someone else.
- Write commit messages that describe the actual change.

## Research history
- Never rewrite history, amend pushed commits, or force-push.
- Do not delete branches or tags. `pre-hackathon` (358da8a) is cited in the paper.
- Do not edit `experiment_log.md` entries, pre-registrations, or results except by appending dated notes.
