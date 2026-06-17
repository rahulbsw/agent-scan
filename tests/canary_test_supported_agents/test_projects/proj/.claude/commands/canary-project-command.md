# canary-project-command

A dummy project-scope slash command used by the agent-scan canary to verify that inspect detects
commands under `<project>/.claude/commands`. The command name derives from this file's name
(`canary-project-command`). No claude CLI creates a standalone project command, so this committed
fixture is the only way to give the scope end-to-end coverage.
