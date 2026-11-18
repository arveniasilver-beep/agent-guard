# agent-guard

A dangerous-command approval gate for [DeerFlow](https://github.com/bytedance/deer-flow)
agents, written as a LangChain agent middleware (`AgentMiddleware`). It intercepts
shell tool calls before they run; if the command is risky, the call is not executed
until the user decides.

Version 0.3.0 · Python >= 3.12 · depends on `langchain>=1.3,<2` and `langgraph>=1.2.9,<1.3`.

## How it works

1. `ApprovalGateMiddleware` wraps every tool call. Only the `bash` tool is gated; the
   command is read from the `command`, `cmd` or `script` argument.
2. `detect()` classifies the command into one of two tiers:
   - **Hardline (floor):** irreversible operations such as recursive delete of `/`,
     system directories or the home directory, `mkfs`, `dd` or redirection to raw
     block devices, a fork bomb, `kill -1`, and shutdown/reboot commands. These always
     go to the user, can never be approved for the whole conversation and are never
     auto-approved. Commands longer than 8,000 characters are treated the same way
     (fail closed).
   - **Dangerous:** risky but recoverable operations (the adapted Hermes pattern list).
3. If the user has not decided yet, the middleware returns an approval card as a
   `ToolMessage` artifact (`{"human_input": ...}`) that the DeerFlow frontend renders
   with **Approve once**, **Approve for this conversation** (not offered for hardline
   commands) and **Deny**. The decision is read back from the message history, and
   "approve once" decisions are tracked as consumed in process memory.
4. Modes, read from `AGENT_GUARD_MODE` on every call (invalid or empty means `manual`):
   - `manual` (default): ask the user for every flagged command.
   - `auto`: for non-hardline commands a second model returns APPROVE, DENY or
     ESCALATE. The command text is treated as untrusted input: shell comments are
     stripped, the command is wrapped in `<command>` tags, at most 4,000 characters
     are sent, and the system prompt tells the judge to ignore embedded instructions.
     Errors or unclear answers escalate to the user.
   - `off`: the gate is disabled.

Other settings: `AGENT_GUARD_JUDGE_MODEL` (judge model name, created through DeerFlow's
model factory) and `AGENT_GUARD_POLICY` (operator rules, appended only to the judge's
system prompt).

## Usage

Register the middleware in DeerFlow's `config.yaml`:

```yaml
extensions:
  middlewares:
    - agent_guard.middleware:ApprovalGateMiddleware
```

`deploy/docker-compose.agent-guard.yaml` is a compose overlay for DeerFlow's Docker
setup: it mounts this directory read-only into the gateway container and adds it to
the backend virtualenv through a `.pth` file. It also carries a few development
conveniences for that container (Playwright cache, Xvfb, image-generation packages).

Tests: `uv sync --extra dev` then `uv run pytest`.

## Known limitations

- **Not yet connected to DeerFlow.** The middleware and the compose overlay exist,
  but agent-guard is not wired into a running DeerFlow deployment and has not been
  verified end to end there.
- **Command chaining bypass class is open.** The hardline rules for `rm` and for
  shutdown/reboot are anchored to the start of a command, and the quote-aware
  pre-pass that splits chained commands
  (`_mark_command_starts()` in `agent_guard/hardline.py`) is not applied before
  matching. Measured on this version: `rm -rf /` alone hits the hardline floor, but
  `true && rm -rf /`, `echo hi; rm -rf /`, `a || rm -rf /`, `ls | rm -rf /` and
  `(rm -rf /)` are only classified as dangerous (so the `auto` judge may approve
  them), and `echo hi; shutdown -h now` or `true && reboot` are not flagged at all.
- Pattern matching only. Hermes Agent's obfuscation normalization (base64 decoding,
  variable expansion, quoting tricks) has not been ported, so deliberate obfuscation
  can get past the gate. The goal is to stop accidental destructive commands.
- User-facing strings and code comments are in Turkish.

## Attribution and license

The dangerous-command patterns and path constants in `agent_guard/patterns.py`, the
hardline patterns and shell-parsing helpers in `agent_guard/hardline.py`, and the
judge design in `agent_guard/judge.py` are adapted from
[Hermes Agent](https://github.com/NousResearch/hermes-agent) by Nous Research,
MIT License. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the notice and
the changes made. No license has been chosen yet for the rest of this code.
