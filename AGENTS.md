<!-- dh:begin -->
## Delivery workflow (dh kit)

This repo uses the **dh kit** for tickets (Jira → branch → tests → PR). The skills and rules come from the `dh` plugin (`dh@native-claude-marketplace`); project settings are in `.claude/dh/profile.yaml`.

If the `dh-*` skills are missing, install the plugin (agents: ask the user first; this needs network):
- **Claude Code:** `/plugin marketplace add git@bitbucket.org:get-native/native-claude-marketplace.git`, then `/plugin install dh@native-claude-marketplace`, then restart.
- **Codex:** `codex plugin marketplace add git@bitbucket.org:get-native/native-claude-marketplace.git`, then `codex plugin add dh@native-claude-marketplace`, then trust `dh-git-guardrails` in `/hooks`.
- **Copilot and other tools:** clone the marketplace repo, copy `plugins/dh/skills/dh-*` to `~/.agents/skills/` and `plugins/dh/dh` to `~/.agents/dh`. These tools get no git guardrail.

Then run `dh-kit-setup` ("set up dh for me") for the rest (Bitbucket tools, guardrail check).
<!-- dh:end -->
