# CLAUDE.md

Project memory for AI assistants working in this repo. Loaded automatically
in every session, including sub-agents in worktrees. Read top-to-bottom
once; the rules don't change session-to-session. Deep content lives in
[`docs/`](./docs/) and [`.claude/rules/`](./.claude/rules/) — this file
points there, never duplicates.

> **Status:** project scaffolding. Source code, README, and `docs/` not yet
> populated. Update §2 (Mission), §3 (Architecture), §8 (Testing) once the
> stack is chosen.

---

## Session ritual — MANDATORY for every session

**This is the #1 priority rule. All other rules are secondary.**
Persistent cross-session memory lives in `plans/`, not in chat history.

### Session start (ALWAYS do this first)
1. **Read [`~/.claude/RTK.md`](~/.claude/RTK.md)** — RTK is mandatory, not a recommendation.
2. **`cat plans/ROADMAP.md`** — canonical roadmap. NEVER delete (per global CLAUDE.md plans-kanban discipline).
3. **`ck plan status`** — see in-flight per-feature plans.
4. Skim recent `plans/reports/` for prior context.
5. **Read [`README.md`](./README.md) if present** — project context before planning.
6. Scan `.claude/rules/*` for the rules layer. Scan available `/ck:*` claudekit skills and pick the right one for the task (see §0.12).

### During work
7. Per-feature plans live in `plans/<date>-<slug>/` managed by `/ck:plan`.
   PR-body convention: `Plan: plans/<date>-<slug>/`. Use `Plan: n/a` for trivial fixes.
8. Sub-agents are briefed on the relevant plan slice + recent reports (see §1).

### Session end (ALWAYS do this before stopping)
9. Append a `## Session note — YYYY-MM-DD` section to `plans/ROADMAP.md`
   summarising what shipped, what's next, blockers.
10. Run `/compact` (§0.11) or `ctx_purge` (§0.10) to preserve session summary.

**Why:** Claude Code loses context across sessions. `plans/ROADMAP.md`
plus per-feature plan dirs are persistent memory. Without the ritual,
the next session starts blind.

---

## §0 Hard rules

### §0.1 No stub code

> "Fully worked code, never write me stupid TODO code without actual logic."

- No `panic("not implemented")`, no empty function bodies, no `// TODO` / `// FIXME` / `// XXX` for behaviour.
- No "scaffolding-only" PRs. Every PR ships logic *and* tests.
- No mocks where real implementations are cheap. In-memory adapters satisfying a port are real implementations.
- Ship end-to-end or descope. Never dead code.

### §0.2 Plan before implement

Every new feature requires a written plan before sub-agent dispatch. Use
`/ck:plan` to author phased plans in `plans/<date>-<slug>/`. Use
`/ck:brainstorm` if architectural options need debate. Use `/ck:research`
for external technology research.

The plan must cover: (1) persona / user research and alternatives; (2)
workflow / journey design; (3) industry-standard inputs where applicable;
(4) data model + interface shape; (5) edge cases + error UX; (6) test
strategy; (7) **owner approval before sub-agent dispatch**.

See [`.claude/rules/primary-workflow.md`](./.claude/rules/primary-workflow.md)
and [`.claude/rules/documentation-management.md`](./.claude/rules/documentation-management.md)
for the full plan file layout (overview + phase files + reports).

> "Do not blindly write code like a stupid student."

### §0.3 Research persists in `docs/references/`

All competitive research, technology evaluation, and architectural
analysis goes in `docs/references/` as permanent Markdown. Check before
researching; write findings into the same PR; never delete (only update
with dated addenda). Use `/ck:research` for research passes.

### §0.4 UI/UX tasks require Preview verification

> "If actual screen is not work as expected, consider task is not done."

Every PR touching UI code MUST be verified visually against a running
stack via `/ck:preview` or the Preview MCP. Code-only lint checks are
necessary but NOT sufficient. **If the page doesn't render correctly or
data doesn't load, the task is NOT done.** Sub-agents doing UI work must
include `/ck:preview` in their workflow.

### §0.5 Naming — full words, not abbreviations

Use **full English words**. Code is read 100× more often than typed;
clarity wins.

**Banned shortenings:** `tmpl` → `template`, `mgr` → `manager`, `svc` →
`service`, `cfg` → `config`, `pwd` → `password`, `req`/`res` →
`request`/`response`, `evt` → `event`, `addr` → `address`, `db` →
`database`, `op` → `operation`, `auth` → `authentication` /
`authorization`.

**Allowed:** UID, URL, URI, JWT, API, SDK, JSON, YAML, XML, HTTP, TCP,
IP, TLS, SSL, DNS, UUID, SHA256, RBAC, CRUD, ctx, err, i/j/k (loops),
t (test), buf, n (count).

**Applies to:** all languages (variables, types, functions, files),
schema (tables/columns), HTTP routes, CLI subcommands, RBAC permissions,
audit-event types, commit messages, PR titles.

**File naming:** kebab-case with long descriptive names — see existing
modularization rule in §Modularization below.

**Enforcement:** code review. Reviewers reject PRs introducing new shortenings.

### §0.6 NEVER work on main — branch first

`main` is protected. ALL changes go through PRs from feature branches.
Before editing ANY file:

```bash
git branch --show-current   # must NOT be "main" or "master"
```

If on `main`, create a branch first:

```bash
git checkout -b <prefix>/<description>
```

**Branch prefixes:** `feat/`, `fix/`, `refactor/`, `docs/`, `chore/`,
`test/`, `security/`, `perf/`, `build/`, `ci/`.

**No exceptions.** Even "quick one-line fixes" go through a branch + PR.
The only operations allowed on `main` are `git pull` / `git fetch`.

Sub-agents get worktree isolation automatically. The orchestrator must
ALSO be on a branch.

### §0.7 Pre-commit hooks

`.pre-commit-config.yaml` is checked into the repo. Install once on a fresh clone:

```bash
brew install pre-commit          # macOS; or pipx / uv / pip
pre-commit install --install-hooks
```

This wires hooks into `.git/hooks/`. From then on:

- **pre-commit stage** (every `git commit`): file hygiene + `cargo fmt --check` + `golangci-lint` + plan-taxonomy guard + shellcheck.
- **pre-push stage** (every `git push`): adds `cargo clippy -D warnings`.
- **commit-msg stage**: `gitlint` validates the commit message structure.

The pre-push hook runs `cargo clippy -D warnings`. For full CI parity before pushing, run `make verify` manually. Bypass
with `git push --no-verify` for emergencies only; never bypass on `main`.

Sub-agents inherit the hook automatically via shared git config in worktrees.

### §0.8 Draft-PR policy + local verify

> **All PRs MUST open as draft. Heavy CI gates on promotion to ready-for-review.**

Workflow:

1. `git checkout -b <prefix>/<name>` (off main, per §0.6)
2. Make changes
3. Run the project's local verify target (lint + test + build)
4. `git push -u origin <branch>`
5. `gh pr create --draft --title "<conv-commit-subject>" --body "..."` (always `--draft`)
6. CI runs lightweight checks (DCO, CLA, etc.) only; iterate until happy
7. `gh pr ready <n>` to promote — now full CI fires
8. Self-merge when green: `gh pr merge <n> --squash --delete-branch`

**Why:** every CI minute on a draft is wasted; local verify catches 95%
of failures faster.

### §0.9 RTK token policy (HARD)

> **HARD POLICY. Same severity as §0.6. Violations waste tokens.**

RTK (`~/.claude/RTK.md`) is the token-optimized CLI proxy. Saves 60–90%
on the operations it covers. **Mandatory**, not optional.

**Single command** — the Claude Code Bash hook auto-wraps the leading
command. No manual prefix needed.

**Chained command** (`&&` / `||` / `;` / `|` / `$(…)` / backticks) — the
hook only sees the leading command. Anything after a chain operator runs
**raw** and dumps full output to context. **Manually prefix `rtk` on
every supported segment.**

```bash
# WRONG — only first git is wrapped; second runs raw
git status && go test ./...

# RIGHT
rtk git status && rtk go test ./...
```

**Long-output commands** — prefer `rtk err <cmd>` (errors/warnings only):

```bash
rtk err npm test                 # only failures + warnings
rtk err pytest                   # only failing tests
```

**Decision flow before any Bash call:**

1. Single command? → write it normally; hook handles the wrap.
2. Chained? → manually prefix `rtk` on every supported segment.
3. Via context-mode MCP? → manually prefix `rtk` on ALL commands — hook doesn't fire through MCP (see §0.10).
4. Output > 20 lines expected? → route through context-mode.

Authoritative current list: `rtk --help`. See `~/.claude/RTK.md` for
the full subcommand catalog.

Violation = token waste (same severity as §0.6). If you catch yourself
running raw, STOP and re-run wrapped.

### §0.10 Context-mode for large-output tools (HARD)

> **HARD POLICY. Same severity as §0.9 RTK. Both rules attack the same failure mode: raw tool output flooding context.**

The `context-mode` MCP server provides sandboxed execution + FTS5-indexed
search. Keeps multi-KB tool output in a side store and feeds only the
relevant slice back to context.

**Decision flow:**

1. Output > ~20 lines expected? → use `mcp__plugin_context-mode_context-mode__ctx_execute` (or `ctx_execute_file` for scripts) instead of raw Bash.
2. Gather + search across many commands? → use `mcp__plugin_context-mode_context-mode__ctx_batch_execute`.
3. Follow-up questions on indexed content? → `mcp__plugin_context-mode_context-mode__ctx_search`.
4. Fetching web content? → `mcp__plugin_context-mode_context-mode__ctx_fetch_and_index` instead of `WebFetch`.
5. After session resume? → `ctx_search(sort: "timeline")` to check prior session memory.

**NEVER use context-mode for file creation/modification.** Use native
`Write` / `Edit` tools. `ctx_execute` / `ctx_execute_file` are for
analysis, processing, computation — not editing.

**RTK vs context-mode:** Both apply. RTK shrinks AT SOURCE; context-mode
keeps OUT OF CONTEXT. Bash hook only fires on native tool — manually
prefix MCP commands with `rtk`.

### §0.11 Compact context before starting a new task

Run `/compact` before:
- Dispatching a sub-agent for a new wave or PR.
- Starting a multi-file refactor.
- Reading `docs/` deeply for an unfamiliar domain.
- After merging a PR and moving to the next slice.
- When the assistant warns about approaching context limits.

`/compact` preserves: decisions, conventions, files touched, open PRs,
in-flight branches. It drops: tool-call output noise, intermediate
diagnostics, completed work transcripts.

### §0.12 Claudekit skill routing (HARD)

> **HARD POLICY. Before reaching for raw tools, check if a `/ck:*` skill fits the task.**

**Default workflow loop:**

```
/ck:plan → /ck:cook → /ck:test → /ck:code-review → /ck:ship → /ck:journal
```

**Quick router** (full tables in
[`.claude/rules/skill-workflow-routing.md`](./.claude/rules/skill-workflow-routing.md)
and [`.claude/rules/skill-domain-routing.md`](./.claude/rules/skill-domain-routing.md)):

| Intent | Skill |
|---|---|
| Plan a feature, design phases | `/ck:plan` |
| Execute an approved plan | `/ck:cook` (or `/ck:cook --fast`) |
| Run tests, check coverage | `/ck:test` |
| Review code before commit/PR | `/ck:code-review` |
| Ship branch → PR | `/ck:ship` |
| Find files / orient in codebase | `/ck:scout` |
| Investigate a bug | `/ck:debug` |
| Fix a known bug | `/ck:fix` (or `/ck:fix --auto`) |
| External research (tech, libs) | `/ck:research` |
| Search library docs | `/ck:docs-seeker` |
| Brainstorm options | `/ck:brainstorm` |
| Adversarial pre-impl review | `/ck:predict` |
| Edge-case decomposition | `/ck:ck-scenario` |
| Security audit (STRIDE/OWASP) | `/ck:security` |
| Document a session | `/ck:journal` |
| EOD session summary | `/ck:watzup` |
| Isolated branch for parallel work | `/ck:worktree` |
| Update project docs | `/ck:docs` |
| Visual aid / diagram / preview | `/ck:preview` |

**When NOT to use a skill:** trivial one-liners, mechanical responses, pure conversation.

**Sub-agent dispatch must include** a sentence stating which skill the
agent should invoke (if any) and which docs to read.

---

## §1 Sub-agent dispatch discipline (HARD)

> **HARD POLICY. Same severity class as §0 hard rules. Sub-agents that ignore these guardrails waste tokens.**

### §1.1 HARD GATE on mandatory reads

Every sub-agent brief MUST open with a "HARD GATE" block listing the
mandatory file reads. Template:

```
## HARD GATE — read files FIRST. If any read is skipped, STOP and exit
## with status=BLOCKED reason="hard-gate read skipped". Do NOT proceed.
## Do NOT burn tokens on the work.
##
## Verification: in your report, include a line for each file:
##   READ: <path> (<line count>)
## If any line is missing, you violated the gate.
##
## Files (read in this order):
## - ~/.claude/RTK.md
## - CLAUDE.md §<sections relevant to task>
## - <plan / phase files>
## - <code files relevant to task>
```

Reports without `READ:` verification lines for every mandatory file =
automatic re-dispatch, or escalate to user.

### §1.2 Dispatch description prefix `<model>: <3–7 word summary>`

Every `Agent` tool call's `description` field MUST be prefixed with the
model tier and a brief summary:

- `haiku: sync phase files for PR #42`
- `sonnet: race-fix terminal-state immutability`
- `opus: cross-cutting refactor of routing layer`

This makes the model tier and scope visible at the dispatch line — no
opaque runs, no surprise escalations. Model floor is **haiku** per
global CLAUDE.md; escalate to sonnet only when haiku stalls; opus only
for cross-cutting architecture.

### §1.3 Token accounting in every sub-agent report

Every sub-agent report MUST end with:

```
TOKENS: input=<n> output=<n> total=<n>
```

The orchestrator aggregates these per-plan into `plan.md` frontmatter or
a `## Token Cost` section so cost-per-plan is visible.

### §1.4 General dispatch rules

1. **Brief in one prompt** — sub-agents have no conversation memory.
2. **Always include in the prompt:**
   - §0.1 ("no stub code, fully working logic, every PR end-to-end").
   - §0.9 RTK rule ("Read `~/.claude/RTK.md` first. Apply manual-prefix rule on every chained Bash command.").
   - §0.10 context-mode rule ("For any expected large output, route through context-mode instead of raw Bash.").
   - §0.12 skill name ("use `/ck:cook` to execute this plan slice").
3. **Reference the approved plan slice** — do not let the agent re-design.
4. **Set `isolation: "worktree"`** so concurrent agents don't collide.
5. **One PR per sub-agent** — branch from `main`, commit signed, push, open PR. **Do not self-merge** (orchestrator's job after CI is green).
6. **Tests are part of the slice**, not a follow-up.
7. Sub-agents read CLAUDE.md automatically — brief them on the slice's specific files, contracts, libraries, test expectations.
8. **Model floor:** haiku default per global CLAUDE.md. Always pass `model` explicitly on the Agent dispatch.

See [`.claude/rules/orchestration-protocol.md`](./.claude/rules/orchestration-protocol.md)
for delegation context, status protocol, and context-isolation rules.

### §1.5 Sub-agents MUST use `/ck:cook` end-to-end — NO raw implementation (HARD)

> **HARD POLICY. Same severity as §0.1 (no stub code). Added 2026-05-22
> after Opus audit found 5 critical stub implementations that would
> silently fail in production. Sub-agents shipped code that compiled,
> passed mock-based tests, and reported "DONE" — but the production
> code paths returned hardcoded empty values, never connected to the
> database, and never called the Rust FFI.**

**Every sub-agent dispatched for implementation work MUST invoke
`/ck:cook` (not raw Write/Edit tools) to handle the full pipeline:**

```
/ck:cook <phase-file-path> --auto
```

`/ck:cook` enforces: plan review → implement → test → code-review →
finalize. Raw implementation (Edit/Write without the skill pipeline)
is **FORBIDDEN** for sub-agents doing implementation work.

#### Why this exists

The 2026-05-22 failure pattern:
1. Sub-agent receives implementation brief with clear spec.
2. Sub-agent writes syntactically valid Rust/Go that compiles.
3. Sub-agent writes unit tests using mock objects → tests pass.
4. Sub-agent reports "DONE — N tests pass, clippy clean."
5. **Production code paths are stubs** — `return Ok(())`, `return ""`,
   `return serde_json::json!([])` — because no live system was ever
   exercised.
6. Orchestrator trusts the report, commits, moves to next phase.
7. **Result: 13,500 lines of skeleton code that silently loses data.**

#### Mandatory verification gate for sub-agents

Before a sub-agent can report "DONE", it MUST demonstrate that the
code **actually works against a live system** (not just compiles +
passes mock tests):

| Layer | Verification command | What it proves |
|---|---|---|
| Rust crate | `cargo test -p <crate>` + at least one test that uses a **real** `tokio_postgres::Client` or a real `deadpool::Pool` (gated on `AGE_TEST_URL`) | The Rust code actually talks to Postgres+AGE |
| Go service | `go test ./go/internal/<pkg>/...` + at least one test that calls **real FFI functions** (gated on compiled Rust dylib) OR `make test-integration` | The Go code actually crosses the FFI boundary |
| GraphQL | A test that sends a real HTTP request to the running server and parses the response | The server actually starts and serves |
| Ingester | A test that enumerates at least 1 resource from a **mock AWS endpoint** (not a hardcoded fixture) and writes it to a real graph | The ingester actually calls AWS APIs and writes data |

**If the sub-agent cannot run the live-system verification** (e.g.,
Docker not running, dylib not compiled), it MUST report
`status=BLOCKED reason="live verification not possible"` — NOT
`status=DONE`. The orchestrator then runs the verification before
committing.

#### Rationalisation trip-wires

If a sub-agent's reasoning includes any of these phrases, the
implementation is likely a stub:

- "In a real implementation, this would..."
- "Placeholder for future integration"
- "Returns empty for now"
- "Will be connected when..."
- "Mock implementation sufficient for v1"
- "Stub — phase N will implement the real logic"
- "Deferred to integration testing"

These phrases in code comments are **§0.1 violations** (no stub code).
Remove the comment AND implement the real logic, or report BLOCKED.

#### Orchestrator's verification duty

The orchestrator (the conversation the user is in) MUST NOT commit
sub-agent output without **personally reading the critical functions**.
For each phase:

1. Read the 2-3 most important functions (pool creation, DB write,
   FFI call-through, query execution).
2. Verify they contain **real logic** (actual SQL execution, actual
   FFI function calls, actual HTTP handlers) — not `return Ok(())`.
3. If any function is a stub, reject the sub-agent's work and
   re-dispatch with explicit "this function was a stub — implement
   the real logic" in the prompt.

**"Sub-agent reports DONE + tests pass" is NOT sufficient evidence
that the code works.** The orchestrator must verify the production
code path, not just the test path.

### §1.6 Commit message convention (HARD)

Every commit message MUST include the component scope in parentheses:

```
<type>(<component>): <subject>
```

**Examples:**
- `feat(activable-schema): production ARN canonicalizer`
- `feat(activable-graph): typed query API with deadpool connection pool`
- `feat(activable-ffi): UniFFI read + write surface (13 exports)`
- `feat(ingest): Go ingestion framework with worker pool`
- `feat(ingest-iam): AWS IAM ingester`
- `feat(graphql): GraphQL API server with gqlgen`
- `fix(activable-graph): resolve clippy expect_fun_call warning`
- `docs(developer): add-service and add-query guides`
- `ci(workflow): cheap-fail-first dependency graph`
- `test(integration): E2E + idempotency gate`

**NEVER** use bare `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`
without a `(<component>)` scope. The component tells the reader WHAT
changed without opening the diff.

**Component naming:** use the crate name for Rust (`activable-schema`,
`activable-graph`, `activable-ffi`), the package path for Go
(`ingest`, `ingest-iam`, `graphql`, `api`), or the infrastructure
concern for CI/docs (`workflow`, `helm`, `docker`, `developer`).

---

## §2 Mission & scope

*(Update once the product brief lands. Currently empty.)*

For roadmap and milestone tracking, see `plans/ROADMAP.md`.

---

## §3 Architecture

*(Update once the stack is chosen. Currently empty.)*

When populated, layer rules go here (e.g. core / ports / adapters /
transports). Per-package details live in `docs/system-architecture.md`.

---

## §4 Testing

- Real implementations preferred over mocks. In-memory adapters
  satisfying a port are real implementations.
- Every exported symbol gets at least one test.
- Tests run without network access unless gated by env.
- Use `/ck:test` as the default entry point.
- **DO NOT** ignore failing tests just to pass the build.
- **DO NOT** use fake data, mocks, cheats, tricks, or temporary
  solutions to pass CI.

See [`.claude/rules/primary-workflow.md`](./.claude/rules/primary-workflow.md) §2 for the full testing workflow.

---

## §5 Git & commits

- Conventional Commits: `<type>(<scope>): <subject>`.
- DCO sign-off (`-s`) on every commit (per global CLAUDE.md).
- No `Co-Authored-By` trailer (per global CLAUDE.md).
- **DO NOT** use `chore` or `docs` types for changes inside `.claude/`.
- **DO NOT** commit `.env`, API keys, database credentials, or any
  secret material.

---

## Hook Response Protocol

### Privacy Block Hook (`@@PRIVACY_PROMPT@@`)

When a tool call is blocked by the privacy-block hook, the output
contains a JSON marker between `@@PRIVACY_PROMPT_START@@` and
`@@PRIVACY_PROMPT_END@@`. **You MUST use the `AskUserQuestion` tool**
to get proper user approval.

**Required Flow:**

1. Parse the JSON from the hook output.
2. Use `AskUserQuestion` with the question data from the JSON.
3. Based on user's selection:
   - **"Yes, approve access"** → Use `bash cat "filepath"` to read the file (bash is auto-approved).
   - **"No, skip this file"** → Continue without accessing the file.

**IMPORTANT:** Always ask the user via `AskUserQuestion` first. Never
try to work around the privacy block without explicit user approval.

---

## Python Scripts (Skills)

When running Python scripts from `.claude/skills/`, use the venv Python
interpreter:

- **Linux/macOS:** `.claude/skills/.venv/bin/python3 scripts/xxx.py`
- **Windows:** `.claude\skills\.venv\Scripts\python.exe scripts\xxx.py`

This ensures packages installed by `install.sh` (google-genai, pypdf,
etc.) are available.

**IMPORTANT:** When skills' scripts fail, don't stop — try to fix them directly.

---

## Modularization

- Files > 200 lines → consider modularizing.
- Check existing modules before creating new.
- Split along logical boundaries (functions, classes, concerns).
- **kebab-case file names** with long descriptive names — file names are
  self-documenting for LLM tools (Grep, Glob, Search).
- Write descriptive code comments.
- After modularization, continue with main task.
- **Skip:** Markdown, plain text, bash scripts, configs, env files.

---

## Documentation management

All important docs live in `./docs/`:

```
./docs
├── project-overview-pdr.md
├── code-standards.md
├── codebase-summary.md
├── design-guidelines.md
├── deployment-guide.md
├── system-architecture.md
└── project-roadmap.md
```

`docs/references/` holds research findings (§0.3). Update protocol and
triggers: see [`.claude/rules/documentation-management.md`](./.claude/rules/documentation-management.md).

---

## Reference docs

| Doc | When to consult |
|---|---|
| [`.claude/rules/primary-workflow.md`](./.claude/rules/primary-workflow.md) | Default implementation flow — plan → code → test → review → ship. |
| [`.claude/rules/development-rules.md`](./.claude/rules/development-rules.md) | File naming, size, quality, pre-commit/push, visual aids. |
| [`.claude/rules/orchestration-protocol.md`](./.claude/rules/orchestration-protocol.md) | Sub-agent dispatch context, status protocol, context isolation. |
| [`.claude/rules/documentation-management.md`](./.claude/rules/documentation-management.md) | Roadmap, changelog, plan file layout. |
| [`.claude/rules/skill-workflow-routing.md`](./.claude/rules/skill-workflow-routing.md) | Default `/ck:*` workflow sequences (§0.12). |
| [`.claude/rules/skill-domain-routing.md`](./.claude/rules/skill-domain-routing.md) | Domain-by-domain skill selector (§0.12). |
| [`.claude/rules/review-audit-self-decision.md`](./.claude/rules/review-audit-self-decision.md) | Audit ≠ auto-reverse; guard user decisions against drift. |
| [`.claude/rules/team-coordination-rules.md`](./.claude/rules/team-coordination-rules.md) | Agent Teams — file ownership, communication, shutdown. |
| [`~/.claude/CLAUDE.md`](~/.claude/CLAUDE.md) | Global rules — DCO, model floor, no-co-author trailer, plans-kanban. |
| [`~/.claude/RTK.md`](~/.claude/RTK.md) | Token-optimized CLI proxy. **Mandatory read** — see §0.9. |

---

**IMPORTANT:** *MUST READ* and *MUST COMPLY* with all *INSTRUCTIONS* in
this file. Especially the **Session ritual** and **§0 / §1 hard rules**
are *MANDATORY. NON-NEGOTIABLE. NO EXCEPTIONS. MUST REMEMBER AT ALL TIMES.*
