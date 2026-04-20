# roblox-opsec

A [Claude Code](https://docs.claude.com/en/docs/claude-code) skill that puts the assistant in the seat of a paranoid senior Roblox application-security engineer. Use it to audit Luau code for exploit surface before you ship a place.

## What this skill does

When active, the assistant treats the **client as adversary-controlled code**: every `RemoteEvent` is a hostile payload, every `LocalScript` Instance reference is an attacker-chosen pointer, every `DataStore` call is a race condition waiting to happen. It audits specifically for:

- Remote abuse: `RemoteEvent` / `RemoteFunction` validation, rate limiting, argument type/bounds checks
- Economy & progression: currency flows, `ProcessReceipt` idempotency, purchase validation
- DataStore: race conditions, `UpdateAsync` vs `SetAsync` misuse, cross-session replay, quota exhaustion
- Physics & character: `Humanoid` state manipulation, teleport/speed detection, `Touched` spoofing
- Interaction: `ProximityPrompt` / `ClickDetector` server-side distance checks
- Backdoors & supply chain: free-model scripts, `require(id)` loading, `getfenv` / `loadstring` usage
- `MessagingService` cross-server fanout, `HttpService` outbound data exfil
- Replication leaks: anything sensitive in `ReplicatedStorage` that belongs in `ServerStorage`
- UI: client-side gating of paid content or admin panels
- Anomaly detection: telemetry hooks worth instrumenting for banwave evidence

## Activation

Claude Code auto-invokes the skill from the description when you use language like:

- "audit this remote", "security review", "check for exploits"
- "harden the economy / data flow / anti-cheat"
- "I'm about to publish — look for problems"
- Pasting code that involves `RemoteEvent`, `DataStore`, `MarketplaceService`, `Humanoid`, `Touched`, etc.

You can also invoke it explicitly:

```
use the roblox-opsec skill to audit ServerScriptService/Shop.lua
```

## Install

Place the skill file at `~/.claude/skills/roblox-opsec/SKILL.md`:

```bash
git clone https://github.com/rib3ye/roblox-opsec.git ~/.claude/skills/roblox-opsec
```

Claude Code discovers user-level skills on next session start. No configuration needed.

To update later:

```bash
git -C ~/.claude/skills/roblox-opsec pull
```

To install project-scoped instead of user-scoped, clone into `.claude/skills/roblox-opsec/` inside a specific project.

## Output format

Findings are reported in this shape so they can be piped to issue trackers or triaged programmatically:

```
[SEV] File:line — Title
  Attack: what the exploiter does
  Impact: what breaks
  Fix: concrete code change
```

Severities: `CRIT`, `HIGH`, `MED`, `LOW`, `INFO`.

## When NOT to use this skill

- Greenfield prototyping where nothing is networked yet
- Pure client-side visual/UI polish with no server state
- Build-tooling / Rojo / CI questions
- Roblox Studio usability issues

For those, use a general coding assistant — the paranoid persona will slow you down with threats that don't apply.

## Contributing

The skill stays sharp only if it tracks the current exploit ecosystem (executor capabilities, Byfron/Hyperion state, new primitives). PRs welcome for:

- New threat entries under `## Threat catalogue`
- Updated hardening patterns that reflect current Roblox API surface
- Corrections when Roblox ships a platform-level mitigation that retires a prior concern

Edit `SKILL.md` directly — frontmatter `name` and `description` are load-bearing for auto-invocation, don't change them without intent.

## License

MIT. Use it, fork it, weaponize it for your own games.
