---
name: coding-workflow
description: End-to-end protocol for conducting any coding project from request to shipped code. ALWAYS use this skill when starting a new feature, project, refactor, bug fix, or any multi-step coding task. Triggers on "build", "implement", "create an app", "add a feature", "fix this", "refactor", or any request that will result in writing or changing code. Enforces spec-driven development, TDD, staged verification gates, and context/token discipline.
---

# Coding Workflow Protocol

You are conducting a software project. Follow these phases IN ORDER. Each phase has an exit gate — do not proceed until the gate passes. Skipping phases to "save time" is how bugs, rework, and token waste happen.

**Effort scaling — decide this first:**
- **Trivial** (typo fix, one-liner, config change): skip to Phase 4, verify, done. Do not write a spec for a one-line change.
- **Small** (single-file change, clear requirements): compress Phases 1–3 into a 5-line plan in your response, then implement + verify.
- **Standard** (new feature, multi-file, anything ambiguous): full protocol.
- **Large** (new system, migration, architecture change): full protocol + break into milestones, each with its own spec/plan/verify cycle.

---

## Phase 0 — Understand Before Touching Anything

1. **Restate the goal in one sentence.** What does the user actually want to accomplish (not just what they literally asked for)? If a better approach exists than the one requested, say so NOW, before any code.
2. **Explore the codebase read-only.** Find relevant files, existing patterns, naming conventions, test setup, package manager, framework versions. Match what exists — never introduce a new pattern when the repo already has one.
3. **Surface ambiguity.** If requirements are unclear, ask 1–3 pointed questions OR state your assumptions explicitly and proceed. Never silently guess on anything expensive to reverse (data models, APIs, auth).

**Gate:** You can state the goal, the constraints, and where the change lives.

## Phase 1 — Spec (Spec-Driven Development)

Write a short spec BEFORE any plan or code. The spec is the contract. Put it in `docs/spec-<feature>.md` (or inline for small tasks):

- **Problem:** one paragraph, why this matters
- **Requirements:** numbered, testable statements ("User can X", "System must Y within Z ms")
- **Acceptance criteria:** the exact observable behaviors that mean "done"
- **Non-goals:** what you are deliberately NOT building (kills scope creep)
- **Edge cases & failure modes:** empty input, duplicates, concurrent calls, network failure, bad data. For anything that fires twice (webhooks, retries): what makes it idempotent?
- **Data model:** if any data is stored/passed, define the shapes FIRST. Bad data models poison everything downstream.

**Gate:** Every requirement is testable. User confirms spec (or you stated it and got no objection for small tasks).

## Phase 2 — Implementation Plan

Turn the spec into a plan in `docs/plan-<feature>.md`:

- **Approach:** chosen architecture + one sentence on why, and one rejected alternative + why not (forces you to actually consider options)
- **Vertical slices:** break work into small, independently verifiable steps. Each slice = something that compiles and passes tests on its own. Order them so the riskiest/most-uncertain slice goes FIRST (fail fast).
- **Files touched:** per slice, list files created/modified
- **Risks:** what could go wrong, how you'll detect it
- **Rollback:** how to undo if a slice goes bad (usually: git revert of that slice's commit)

**Gate:** No slice is bigger than ~1 focused session. Riskiest slice is first.

## Phase 3 — Tests First (TDD)

For each slice, write the tests BEFORE the implementation:

1. Translate acceptance criteria + edge cases into failing tests (red).
2. Run them. **Confirm they fail for the right reason.** A test that passes before implementation exists is testing nothing.
3. Tests assert BEHAVIOR (inputs → outputs, state changes), not implementation details. Don't test private internals.
4. Include: happy path, each edge case from the spec, and at least one failure-mode test (bad input, dependency down).

**Hard rules — never violate:**
- NEVER modify a test to make it pass. If a test is wrong, say so explicitly and fix it with justification.
- NEVER delete, skip, or comment out a failing test to "get green."
- NEVER mock the thing you're actually testing. Mock external boundaries only (APIs, DBs, clocks).
- NEVER hardcode expected values into implementation to satisfy a test (reward hacking).

**Gate:** All new tests exist and fail for the right reasons.

## Phase 4 — Implement

Work one slice at a time:

1. Write the minimum code to turn the slice's tests green.
2. Run the slice's tests. Green → refactor for clarity while keeping green (red-green-refactor).
3. Run the FULL suite + linter + typechecker after every slice, not just at the end. Regressions are cheap to fix when they're one slice old.
4. Commit per slice with a conventional message (`feat:`, `fix:`, `refactor:`, `test:`). Small commits = free rollback points.
5. **Secrets hygiene:** never hardcode keys/tokens. Env vars or secret manager only. Never commit `.env`. If you ever see a real key in code, flag it for rotation immediately.
6. Stay inside the spec. New ideas mid-build go into a `LATER.md` note, not into the code.

**Gate per slice:** slice tests green, full suite green, lint/typecheck clean, committed.

## Phase 5 — Verification & Review

Before declaring done:

1. **Full suite verification:** all tests, lint, typecheck, and a real build (`npm run build` / equivalent). A passing test suite with a failing build is not done.
2. **Self-review the diff:** read `git diff main` as if reviewing a stranger's PR. Look for: dead code, debug logging, TODO-that-should-be-now, inconsistent naming, missing error handling, secrets.
3. **Adversarial pass:** with fresh eyes (or a subagent with clean context), try to break it — the spec's edge cases plus anything the tests missed. In a fresh context, review the code WITHOUT seeing the implementation conversation; conversation bias makes you blind to your own mistakes.
4. **Trace acceptance criteria:** walk the spec's criteria one by one and name the test or manual check that proves each. Any criterion with no proof → not done.
5. **Smoke test the real thing:** run the actual app/endpoint/script once end-to-end. Tests lie; running it doesn't.

**Gate:** Every acceptance criterion has proof. Build passes. Diff is clean.

## Phase 6 — Ship & Record

1. Update docs/README if behavior or setup changed.
2. Summarize for the user: what was built, what was verified, known limitations, what's in LATER.md.
3. If a bug was fixed: state root cause in one sentence. If you can't, you patched a symptom.

---

## Token & Context Discipline (applies to every phase)

Wasted tokens come from re-reading, re-explaining, and rework. Prevent all three:

- **Externalize state.** Spec, plan, and a `progress.md` (current slice, what's done, next step) live in FILES, not conversation memory. If context compacts or the session dies, any agent can resume from the files in one read.
- **Search, don't dump.** Use grep/glob to find the exact lines you need. Never cat whole large files into context. Read a file once; take notes in progress.md instead of re-reading.
- **Delegate exploration.** Use subagents for wide codebase exploration or research — they burn their own context and return a summary, keeping the main thread lean.
- **One slice per context.** For large projects, finish + commit a slice, update progress.md, then continue (or start fresh) rather than dragging 100k tokens of stale history.
- **Fail fast beats retry loops.** If the same error survives 2–3 fix attempts, STOP. Re-read the actual error message, add a diagnostic print/log, or read the relevant source. Blind retry loops are the #1 token furnace.
- **Plan tokens are the cheapest tokens.** A 500-token plan routinely saves 20k tokens of rework. Never skip Phase 2 to "move fast."

## Debugging Protocol (when something breaks)

1. Read the FULL error/stack trace. The answer is usually in it.
2. Reproduce it with the smallest possible case — ideally a new failing test (which then becomes a permanent regression guard).
3. Form ONE hypothesis, add ONE log/assertion to test it, run, read output. Repeat.
4. Fix root cause, keep the regression test, remove debug logging, commit as `fix:`.
