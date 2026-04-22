# roblox-opsec

A [Claude Code](https://docs.claude.com/en/docs/claude-code) skill that puts the assistant in the seat of a paranoid senior Roblox application-security engineer. Use it to audit Luau code for exploit surface before you ship a place.

## What this skill does

When active, the assistant treats the **client as adversary-controlled code**: every `RemoteEvent` is a hostile payload, every `LocalScript` Instance reference is an attacker-chosen pointer, every `DataStore` call is a race condition waiting to happen. It audits specifically for:

- Remote abuse: `RemoteEvent` / `RemoteFunction` / `UnreliableRemoteEvent` validation, rate limiting, argument type/bounds checks, state-machine ordering, replay/cardinality, outbound payload leakage
- Economy & progression: currency flows, `ProcessReceipt` idempotency, purchase validation, **cross-server / server-hop dup**, daily-reward replay
- Trading systems: switcheroo, partner-disconnect dup, stale-offer races, item-id forgery, cross-server trade brokering
- DataStore: race conditions, `UpdateAsync` vs `SetAsync` misuse, cross-session replay, session locking, quota exhaustion, schema versioning
- Physics & character: `Humanoid` state manipulation, teleport/speed detection, `Touched` spoofing, **NetworkOwnership flings / ram exploits**
- Interaction: `ProximityPrompt` / `ClickDetector` server-side distance, ownership, prerequisites, and `Enabled` re-validation
- Backdoors & supply chain: free-model scripts, `require(id)` loading, `loadstring` / `getfenv` usage, **obfuscated loaders** (`string.char` reconstruction, base64/hex decoding, instance-name regex extraction), **off-screen / whitespace / bidi-override payloads**, Studio-plugin compromise
- `MessagingService` cross-server fanout, `HttpService` outbound data exfil, Open Cloud key hygiene
- Teleport / cross-place: `TeleportData` mutability, reserved-server bearer tokens, cross-experience trust
- Replication boundary: any `ModuleScript` the client can `:FindFirstChild` is fully readable; embedded webhook URLs / API keys / admin UserIds / anti-cheat thresholds in client-visible code
- StreamingEnabled is a bandwidth optimisation, not a visibility boundary
- Animation / `HumanoidDescription`: rig-displacement exploits, oversized accessories, client-supplied `AnimationId`s
- UI: client-side gating of paid content, admin panels (`UserId` not `Name`, server-side `GetRankInGroup` with fail-closed cache)
- Chat / `TextService` filtering, command surfaces, `PolicyService` advisory vs security
- Anomaly detection: per-player anomaly counters, **free honeypots** on every `S→C`-only remote, banwave evidence and what to log
- Typed-remote frameworks: **Zap (red-blox)** audit — schema-as-validation pitfalls, the `unknown` opt-out, mandatory user-side rate limiting (issue #219 server-crash mitigation), `PlayerRemoving` Fire-leak (#216), Zap-native honeypot pattern, generated-file placement, CLI/Zappy supply chain

## Activation

Claude Code auto-invokes the skill from the description when you use language like:

- "audit this remote", "security review", "check for exploits"
- "harden the economy / data flow / anti-cheat"
- "dupe / dup / duplication exploit", "server hop"
- "exploit kit / executor / Synapse / Wave / Solara / Xeno"
- "ban wave / banwave"
- "I'm about to publish — look for problems"
- Pasting code that involves `RemoteEvent`, `DataStore`, `ProfileStore`, `MarketplaceService`, `ProcessReceipt`, `Humanoid`, `Touched`, `ProximityPrompt`, `TeleportService`, `MessagingService`, `HttpService`, etc.

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

## File layout

- `SKILL.md` — the persona, triage workflow, insecure-defaults cheat sheet, threat catalogue (one-paragraph essence per category), hardening code patterns, output/voice conventions. Read every time the skill is invoked.
- `reference.md` — long-form deep-dives the agent reads on demand when auditing a specific category: full cross-server-dup taxonomy, the network-ownership/fling playbook, the obfuscated-loader catalogue, the off-screen/whitespace-payload audit procedure, the unreliable-remote threat model, the canonical trade flow, ProcessReceipt edge cases, lag-compensated hit detection, Open Cloud key hygiene, Studio-plugin supply chain, animation/HumanoidDescription exploits, banwave methodology, **the Zap (red-blox) audit playbook** (recognition fingerprints, option-by-option / event / funct / type pitfalls, full mitigations for issues #219 and #216, Zap-native honeypotting, generated-file placement, build/supply-chain hygiene, migration sanity check), and a glossary of executor jargon.

## Contributing

The skill stays sharp only if it tracks the current exploit ecosystem (executor capabilities, Byfron/Hyperion state, new primitives). PRs welcome for:

- New threat entries under `## Threat catalogue` in `SKILL.md` (with the deep-dive going into `reference.md`)
- New entries in the `## Insecure defaults` cheat sheet — patterns concrete enough to flag on sight
- Updated hardening patterns that reflect current Roblox API surface
- Corrections when Roblox ships a platform-level mitigation that retires a prior concern
- Updates to the executor glossary when the scene shifts

Edit `SKILL.md` directly — frontmatter `name` and `description` are load-bearing for auto-invocation, don't change them without intent. Prefer adding the actionable summary to `SKILL.md` and the long-form taxonomy to `reference.md` so the main file stays scannable.

## License

MIT. Use it, fork it, weaponize it for your own games.
