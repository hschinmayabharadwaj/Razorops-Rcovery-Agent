# Razorops--Agent For Payment Recovery (multi-flow) — Go port

## Razorpay test checkout

The Blazor dashboard in `gateway-ui/` includes a Razorpay test-mode checkout.
The server creates orders and verifies payments; the browser receives only the
public key ID. Configure test credentials as environment variables before
starting the UI. Never commit these values or put the secret key in browser
code:

```powershell
$env:RAZORPAY_KEY_ID="rzp_test_..."
$env:RAZORPAY_KEY_SECRET="..."
$env:RAZORPAY_WEBHOOK_SECRET="..."
dotnet run --project .\gateway-ui\GatewayUI.csproj
```

The C# host exposes:

- `POST /api/payments/razorpay/order` — creates an INR order; amount is in paise.
- `POST /api/payments/razorpay/verify` — verifies the Checkout.js payment signature.
- `POST /webhooks/razorpay` — validates the `X-Razorpay-Signature` HMAC and records
  accepted events in `data/payment-webhooks.jsonl`.

In the Razorpay test dashboard, set the webhook URL to the public HTTPS URL
for `/webhooks/razorpay` and use the same value as `RAZORPAY_WEBHOOK_SECRET`.
For local testing, expose the UI with an HTTPS tunnel such as ngrok or
Cloudflare Tunnel. The current audit stream remains a separate Go service on
`http://localhost:8090`.

An AI agent that **detects revenue at risk, determines the right intervention,
and executes a bounded recovery workflow** across 7 recovery flows —
from payment failures and checkout abandonment to overdue receivables.

Recovery is a **state machine**, not a chatbot. Every money-moving / stopping
decision is made by **named policy rules** (`policy_engine`) — never by an LLM.
The only LLM seam is generating human-readable customer copy **after** a
decision has already been made.

This repository is a **from-scratch Go port** of the original TypeScript
implementation, preserving architecture, behavior, and outputs exactly
(deterministic 60-event batch, hash-chained audit log, tuning sandbox, risk
prescore, security stack). A single package `rz` (one file per module) plus
8 command-line drivers under `cmd/`.

**Why this exists (60-second pitch).** Revenue leaks across payment failures,
checkout drops, failed subscriptions, overdue receivables, UPI mandate failures,
and missed calls — not in one clean step. Razorpay's own **Vulcan** foundation
model proves pattern-based payment intelligence is where the industry is headed,
but it is closed, proprietary, and locked to their rails (no checkpoint, no
third-party API, no dataset). This project is the **auditable, merchant-portable,
compliance-first version of that same idea, for the recovery layer** — a
deterministic engine whose stopping decisions and every audit entry are provable,
measured, and hash-chained, not self-reported. The naive-vs-real comparison and
live tamper demo below make that the story a judge can see in under a minute.

## Repository layout

```
razor_gateway/
  go/                         # Recovery engine (Go module razor_gateway/go)
    cmd/                      #   one CLI per stage + stream-server (HTTP/SSE adapter)
    rz/                       #   engine package: rules, state machine, audit chain, HTTP adapter
      *_test.go               #   unit tests, fuzz targets
      integration_test.go     #   end-to-end: real batch -> real audit log -> real HTTP handler
    data/flows/               #   canonical 60-event batch
  gateway-ui/                 # Blazor Server dashboard + Razorpay test checkout (.NET 10)
    Components/               #   pages, layout, shared components
    Endpoints/                #   minimal-API route mapping (PaymentEndpoints)
    Services/                 #   RazorpayPaymentService, PaymentAuditService, Go API + SSE clients
    Models/                   #   DTOs mirroring the Go adapter's JSON
  tests/
    GatewayUI.Tests/          # xUnit tests for gateway-ui
      Unit/                   #   services in isolation (stubbed HTTP, temp audit file)
      Integration/            #   the real app in-memory via WebApplicationFactory
      TestSupport/            #   shared fakes: stub HTTP, test secrets, temp files
  .github/workflows/ci.yml    # build + vet + test for both stacks on every push / PR
  RazorGateway.slnx           # .NET solution (app + tests)
```

## End-to-end flow

Every box maps to real code in this repo (file = `go/rz/*.go`):

```
[Merchant checkout/subscription event]
        │
        ▼
[Razorpay Webhook] ──HMAC-SHA256 verify──> reject if invalid/replayed   (webhook.go)
        │ (valid, verified event)
        ▼
[Idempotency check] ──already processed?──> short-circuit, no duplicate action   (store.go Claim — atomic, restart-safe)
        │ (new event)
        ▼
[classify()] — deterministic, no LLM — reason_bucket assigned           (classify.go)
        │
        ▼
[Risk Prescore] — pure factor scoring — logged BEFORE decision          (riskscore.go, prescore.go)
        │
        ▼
[Policy Engine / State Machine] — named rules evaluated in fixed order:
    fraud? → suppress          mandate_revoked? → escalate            (rules.go, engines.go,
    at_touch_cap? → abandon    at_retry_max? → escalate                 statemachine.go)
    active_PTP? → suppress     else → retry/contact/execute
        │
        ▼
[Execution layer] — idempotency-keyed call to Razorpay API (retry/charge)  (execution.go)
        │
        ▼
[LLM copy seam] — ONLY generates customer-facing text, validated for injection  (copy.go, llm.go)
        │
        ▼
[Audit log] — append-only, hash-chained, externally anchored, PII-redacted at read  (store.go, chain.go, anchor.go, redact.go)
        │
        ▼
[Metrics + Exception report] — computed FROM the log, never asserted    (metrics.go, copy.go)
```

## The 7 flows

| Flow | Detects | Intervenes with |
|------|---------|-----------------|
| `payment_degradation` | success-rate drop / latency spike / issuer down | degrade alert → gateway re-routing → escalate |
| `checkout_abandonment` | dropped cart/checkout step | reminder + cart incentive (cost-aware) |
| `failed_subscription` | `subscription.charged.failed` | retry budget → escalate / suppress |
| `b2b_receivables` | overdue invoice (net30/net60) | tiered dunning, dispute hold |
| `mandate_retry` | UPI Autopay / e-NACH failure | NPCI retry-window sequencing |
| `hinglish_voice` | missed call / callback / unreachable | Hinglish voice call (TRAI quiet-hours + DNC aware) |
| `promise_to_pay` | committed / missed / broken PTP | suppress until date, remind 24h before, follow up |

## Architecture

The Go port lives in `go/` as a single package `rz` (module `razor_gateway/go`),
with one file per original TS module:

```
go/
  cmd/
    gen-events        # generate the deterministic 60-event batch -> data/flows/*.json
    run-batch         # full batch run -> audit log + metrics + table + exceptions
    verify-audit      # verify the tamper-evident hash chain
    compare-policy    # REAL vs NAIVE policy comparison + compliance lift
    prescore          # prevention layer: predict-before-fail report
    sandbox           # tunable sweep backtester + locked-rule invariant
    security          # security posture demo (webhook/auth/redaction/anchor/LLM/secrets)
    demo              # walkthroughs: mandate_revoked, NPCI window, checkout incentive
  rz/
    types.go          # unified domain: FlowType, states, narrowed taxonomy, audit schema
    generate.go       # deterministic PRNG (mulberry32, seed 20260201) -> configurable batch
    classify.go       # classify(event)->reason_bucket per flow (no LLM)
    rules.go          # NAMED stopping rules (pure, unit-tested; tunable vs locked)
    engines.go        # pure per-flow decision functions
    statemachine.go   # pure state transition + audit entry
    execution.go      # execute the decided action (retry / contact / voice / incentive)
    copy.go           # LLM copy seam (ONLY post-decision text generation)
    store.go          # append-only JSONL audit log (auto hash-chains) + atomic idempotency Claim
    chain.go          # sha256 hash-chain primitives + verifyChain
    naive.go          # deliberately-naive baseline (no safety rules)
    compare.go        # REAL vs NAIVE + compliance violation counting
    config.go         # TUNABLE vs LOCKED separation + JSON tunables-file loader
    sandbox.go        # tunable sweep backtester + locked-rule invariant
    riskscore.go      # pure multi-factor predictor (named factors, no black box)
    prescore.go       # retroactive predict-before-fail report + audit emission
    webhook.go        # HMAC-SHA256 webhook signature verification (Razorpay scheme)
    auth.go           # access control (deny-by-default role matrix)
    redact.go         # PII redaction for log / exception read surfaces
    anchor.go         # external append-only anchor for the hash chain
    llm.go            # LLM output validation (customer-facing seam)
    secrets.go        # env-only, fail-closed secrets (never committed)
    metrics.go        # metrics computed FROM the audit log
    table.go          # audit-log table + metrics view
    runner.go         # unified orchestrator (idempotency gate + per-customer touch caps)
  rz/*_test.go        # 14 test files: 113 tests + 5 fuzz targets (see Testing section)
  rz/integration_test.go # batch -> audit log -> HTTP handler, over a real loopback connection
  rz/hardening_test.go   # admin-override guard, redaction edge cases, atomic tunables, log limits
  rz/fuzz_test.go     # native Go fuzz targets: classify / parse / verify / redact / LLM
  rz/contract_test.go # golden contracts: Razorpay payloads, error-code table, HMAC KAT, redaction
  rz/idempotency_test.go # at-most-once gate: replay suppress + concurrent delivery race test
  rz/generator_test.go   # canonical 60-event parity lock + scaling/per-flow/seed knobs
  rz/config_test.go      # tunables-file loader: apply / reject unknown + locked keys
```

## Stopping rules (all named + unit tested first)

- `MAX_RETRY_ATTEMPTS = 3` per invoice — `atMaxRetryAttempts()`
- `fraud_flagged` -> suppress immediately — `fraud_suppress`
- `mandate_revoked` -> escalate to human, never retry — `mandate_revoked_escalate`
- active promise-to-pay date -> suppress all touches until it passes — `promise_to_pay_suppress` / `ptp_suppress`
- 3 failed retries -> escalate, no infinite loop — `exhaust_attempts_escalate`
- Max 3 outbound touches per customer (per-customer across the batch) — `atTouchCap()`
- **Mandate retry window** (NPCI): bounded sequencing, not "retry every 3 days" — `mandate_retry_window` / `mandate_retry_seq`
- **Checkout spam guard**: only repeat visitors, no discount on junk carts — `repeat_visitor_only` / `cart_incentive`
- **B2B dunning ladder**: net30 remind → net60 collections → legal; disputes held — `receivable_*` / `dispute_hold`
- **Voice regulatory**: TRAI quiet hours (21:00–09:00 IST) + DNC honored — `voice_do_not_call`
- **PTP compliance**: large PTPs need human supervisor sign-off — `ptp_missed_escalate`
- Batch capacity cap via single constant — `MAX_BATCH_ATTEMPTS`

Every transition writes `{event_id, timestamp, flow, reason_bucket, rule_fired,
decision, actor, outcome}` to the append-only audit log. The log is also a
**tamper-evident hash chain** (see below).

## Tamper-evident audit log (hash chain)

Each audit entry carries two extra fields (`prevHash`, `hash`) added on top of
the existing schema — no existing field is changed.

- `prevHash` = the `hash` of the immediately preceding entry (`GENESIS_HASH =
  "0"*64` for the first).
- `hash` = `sha256(prevHash + stable_stringify(entry minus hash fields))`.
  Keys are sorted before stringify so the hash reproduces exactly.

Pure functions in `go/rz/chain.go`:
- `AppendAuditEntry(log, newEntryData)` — pure append (no mutation).
- `VerifyChain(log)` — recomputes every hash and returns the first broken index.

```bash
go run ./cmd/run-batch     # writes a hash-chained audit log
go run ./cmd/verify-audit  # ✓ chain verified, N entries, no tampering detected
```

**Demo trick:** run the batch, `verify-audit` passes. Edit one line of
`go/data/audit.log.jsonl` (e.g. flip a `decision`), re-run `verify-audit` — it
prints `✗ chain broken at entry N`.

## Naive-policy baseline & compliance lift

`go/rz/` runs the REAL policy engine and a deliberately-NAIVE one over the
IDENTICAL 60-event batch, and measures the compliance lift:

- `naive.go` — a baseline with NO safety rules: blindly retries every failure
  every 3 days up to 10 attempts regardless of reason bucket (including
  `fraud_flagged` and `mandate_revoked`), no touch cap, no DNC/quiet-hours check,
  no PTP suppression.
- `compare.go` — runs both, then re-checks **every naive action against the real
  rule predicates** (`isFraudFlagged`, `isMandateRevoked`, `isDoNotCall`,
  `atTouchCap`, `atMaxRetryAttempts`, `hasActivePromiseToPay`) and counts the
  exact violations the naive policy would commit. Nothing is hand-waved.

```bash
go run ./cmd/compare-policy
```

Outputs a table + a data-computed one-line takeaway, e.g.:
*"Naive retry recovers 87.7% vs 61.5% (+26.3pp) but commits 65 compliance
violations (20 fraud retries, 40 mandate revoke retries, 42 touch-cap breaches,
42 retry-budget breaches, 4 PTP breaches) ... — violations our policy engine
structurally cannot make."*

## Constraints honored

- **No LLM call ever makes a retry/stop/escalate decision.** LLM (`llm_copy`) is
  used only for: (a) generating customer copy, (b) summarizing the exception list.
- Every money-moving action traces to a **named rule**, not "the model decided."
- Recovery metrics are **computed from the audit log**, not asserted.

## Prevention layer: risk prescore (predict-before-fail)

The recovery layer is, by definition, reacting after a leak. This module is the
bridge to becoming a **risk manager** instead of a cleanup crew.

`go/rz/riskscore.go` scores every customer BEFORE the attempt using **named,
inspectable factors** — `prior_decline_count_90d`, `mandate_age_days`,
`days_since_last_decline`, `prior_chargeback_count_90d`, `card_expiry_within_60d`.
No black box: each factor contributes visible points, sum → `low|medium|high`.

`go/rz/prescore.go` runs that score **retroactively over the same batch** and
compares pre-score against the ACTUAL outcome (drawn from the verified audit
log), then emits each prescore as a hash-chained audit entry (zero schema change).

```bash
go run ./cmd/prescore
```

Output (computed, not claimed):
*"25 of 28 events that were not auto-recovered (89% recall) had already been
flagged high-risk BEFORE the attempt (49% precision)."*

This is the same thesis as **Razorpay's Vulcan** (pattern-based payment
intelligence at massive scale) — but transparent (named factors vs. undisclosed
"3,000 signals"), merchant-portable (a pure function over your own data, not
locked to Razorpay's rails), and compliance-native (the prescores are themselves
hash-chained). The honest framing: *Vulcan validates the direction; ours is the
auditable, portable version of it, for the recovery layer.*

## Backtest sandbox: tunables move, LOCKED rules don't

`go/rz/config.go` separates rules into two kinds:

- **TUNABLE** — business levers (`maxRetryAttempts`, `maxTouchesPerCustomer`,
  `checkoutReminderCap`, `maxVoiceCalls`, `cartIncentiveThreshold`,
  `ptpSupervisorThreshold`, `mandateWindowDays`, `receivableTier2Days`). Raise or
  lower these; recovery/touches move with them.
- **LOCKED** — hard safety/compliance invariants (`fraud_suppress`,
  `mandate_revoked_escalate`, `voice_do_not_call`, TRAI `quiet_hours`). Their
  predicates accept NO tunable, so no configuration can disable them.

`go/rz/sandbox.go` re-runs the SAME batch under a tunable sweep:

```bash
go run ./cmd/sandbox
```

```
scenario       recovery  touches  cost/rec  locked_viol
baseline       61.5%     81       2.53/rec  0
aggressive     63.6%     83       2.44/rec  0
conservative   16.6%     43       8.60/rec  0
high_incentive 61.5%     81       2.53/rec  0
✓ Locked safety/compliance rules never budge across any tunable sweep
```

## Tunables from a config file (compliance-sourced, not code-sourced)

Thresholds are business/compliance numbers and should live beside their
rationale, not inside code. `go/tunables.example.json` ships the current
defaults; `run-batch` and `compare-policy` accept `-config`:

```bash
go run ./cmd/run-batch -config tunables.example.json
```

`LoadTunablesFile()` (config.go) applies them atomically. The key whitelist is
the **entire** tunability surface, so an unknown key or a typo fails loudly
instead of silently doing nothing — and the LOCKED invariants (fraud,
mandate_revoked, DNC, TRAI quiet-hours) have **no config key at all**, so no
config file can ever override them.

| Key | Unit | Default | Rationale (source) |
|-----|------|---------|--------------------|
| `max_retry_attempts` | attempts | 3 | retry budget; dwell on stuck accounts is a refund/fraud risk |
| `max_touches_cap` | touches/customer/batch | 3 | blast-radius cap; customer-experience ceiling |
| `checkout_reminder_cap` | reminders | 2 | spam guard (checkout remediation) |
| `voice_call_cap` | calls | 2 | voice outreach ceiling |
| `cart_incentive_threshold` | paise | 50000 | no discount on junk carts |
| `ptp_supervisor_threshold` | paise | 2000000 | high-value PTPs need human sign-off (dual control) |
| `mandate_retry_window` | days | 3 | NPCI / UPI Autopay retry window |
| `receivable_tier2` | days | 60 | net30 → net60 collection boundary |

## Concurrency & idempotency (at-most-once)

A webhook receiver that has money-moving actions must be **idempotent**:
the same event delivered twice (network retry, audit-replay, malicious copy)
must not charge twice. The engine enforces at-most-once end-to-end:

- `AuditStore.Claim(eventId)` (store.go) is an **atomic** check-and-mark,
  serialized by the store mutex. The first caller wins; every later caller —
  including concurrent goroutines — is told the event was already processed.
- The claim horizon **survives process restarts**: a store opened over an
  existing log hydrates all processed IDs from it, so a restarted process still
  refuses to re-execute an old event.
- A duplicate delivery is **audited, not ignored**: one
  `duplicate_suppress` entry is chained so the log proves dedup happened (and a
  malicious duplicate can't hide evidence).
- Metrics ignore `duplicate_suppress` rows (they stay in the chain for
  integrity but are not business activity), so replay can't distort recovery
  numbers.

Testing: `idempotency_test.go` re-delivers the whole 60-event batch and asserts
zero re-execution, and fires the same event from 16 goroutines at once,
asserting exactly one execution. `go test -race` on a 64-bit toolchain
exercises the mutex for real (see Commands).

## Failure modes & fallbacks (honest table)

| Component | Failure | Impact | Fallback | Tested? |
|-----------|---------|--------|----------|---------|
| Razorpay webhook | bad/replayed signature | forged event enters engine | reject before classify (`webhook.go`) | yes |
| Webhook timestamp | outside 5-min skew | replay legitimately doubles a charge | reject as expired (bank transfer already settling is safe) | yes |
| Raw payload shape | not the normalized envelope | event silently dropped | `ParseTrustedEvent` returns `ok=false` → 400 to caller; adapter is the documented merchant-side seam | yes (contract) |
| Duplicate eventId | double charge / double touch | charged twice | `Claim` at-most-once + `duplicate_suppress` audit row | yes |
| JSONL audit write | disk full / i/o error | decision already taken but not logged | `Append` returns error **before** `ExecuteAction` runs in the same step (audit-before-action ordering in runner.go:86→93); batch aborts, no partial execution | yes (ordering asserted by construction) |
| Store corruption | mid-write crash | chain tail invalid | append-only JSONL; a corrupted/truncated line fails JSON parse and surfaces as a loud error; `verify-audit` flags any mismatch | no (crash-injection not simulated) |
| LLM copy | prompt injection / PII / overlong | malformed customer message | `llm.go` fails closed (reject-or-censor at boundary); LLM never decides | yes |
| Retry loop | runaway retries | infinite touches | fixed `max_retry_attempts` + `max_batch_attempts` caps | yes |
| Tunable config | bad key / non-integer | silently ignored typo | `LoadTunablesFile` errors on unknown key; atomic apply | yes |
| Concurrent deliveries | last-write-wins double exec | double charge | atomic `Claim` (mutex-serialized) | yes |
| Race detector build | 32-bit gcc on Windows | `-race` won't link | needs 64-bit gcc/clang (TDM-GCC) or Linux; mutex story verified by inspection + concurrency test | env-limited |

## Threat model (STRIDE walk-through)

| Threat | Where it hits | Mitigation |
|--------|---------------|------------|
| **Spoofing** | webhook → engine | HMAC-SHA256 signature + timestamp skew (webhook.go); deny-by-default auth on all CLI actions (auth.go) |
| **Tampering** | audit log | hash chain + external anchor (chain.go, anchor.go); PII redaction does not weaken integrity |
| **Repudiation** | "who decided to charge?" | every transition is a signed-by-chaining (prevHash/hash) audit row naming `rule_fired` + `actor` |
| **Info disclosure** | exception list / dashboard | presentation-time redaction of PII (redact.go); secrets env-only + `redactSecret()` on output |
| **DoS** | replay flood / huge body | 5-min skew window; duplicate events short-circuit to a no-op audit row instead of re-executing; body size not yet bounded (gap below) |
| **Elevation** | config file | tunables whitelist — LOCKED compliance rules have no key to override (config.go) |

Residual, explicitly out of scope: real identity/session layer, TLS at the
edge, DPDP data-retention/deletion, anomaly detection on engine behavior.

## One command runs everything

```bash
go run ./cmd/demo
```

The demo CLI runs the real batch plus walkthroughs proving correct behavior:
- **mandate_revoked** handled gracefully (refuses to retry, escalates),
- **mandate retry** sequenced within the NPCI retry window (India-specific),
- **checkout abandonment** recovered cost-aware (spam guard + incentive threshold).

`compare-policy`, `prescore`, and `sandbox` each run their own stage of the full
story as standalone CLIs (the original TS `e2e` bundled all of them together).

## Razorpay test checkout (Blazor UI)

The `gateway-ui` project includes a Razorpay test-mode checkout flow:

- `POST /api/payments/razorpay/order` creates an order server-side.
- Razorpay Checkout.js opens in the browser using only the public key ID.
- `POST /api/payments/razorpay/verify` verifies `order_id|payment_id` with HMAC-SHA256.
- `POST /webhooks/razorpay` verifies the raw body with the Razorpay webhook secret,
  rejects invalid signatures, and ignores duplicate payment events.
- Accepted payment events are written to `data/payment-webhooks.jsonl` as a
  separate hash-chained integration audit stream.

Set test credentials in the shell that starts the C# app. Never commit these
values or put the API secret in Razorpay Checkout JavaScript:

```powershell
$env:RAZORPAY_KEY_ID="rzp_test_..."
$env:RAZORPAY_KEY_SECRET="..."
$env:RAZORPAY_WEBHOOK_SECRET="..."
dotnet run --project .\gateway-ui\GatewayUI.csproj
```

In the Razorpay Dashboard, create a test webhook pointing to:
`https://your-public-host/webhooks/razorpay`. For local development, expose
the app with an HTTPS tunnel and use that tunnel URL. Select payment events
such as `payment.captured`, `payment.failed`, and `order.paid`.

The dashboard's **Create payment** action uses a fixed INR test amount of
`12,400.00` until a merchant checkout form is added. Razorpay test mode does
not move real money.

## Security posture (honest, tested — not claimed)

The security stack mirrors the TS original module-for-module. `go run
./cmd/security` demos each defense live, and `go test` proves them.

**Implemented & tested (`go/rz/security_test.go`, 25 cases):**
- **Webhook signature verification** (`webhook.go`) — Razorpay's `t=<ts>|s=<hmac>`
  HMAC-SHA256 scheme, plus 5-minute replay-window check. No event is trusted as
  an input until it passes this gate. Constant-time compare; signature mismatch,
  replay, and tampered-body are all rejected.
- **Access control, deny-by-default** (`auth.go`) — every privileged action
  (`run_batch`, `tune_sandbox`, `read_audit_log`, …) is gated behind a
  caller-supplied credential + a role matrix (`operator`/`admin`/`auditor`).
  Unknown credentials and missing keys are rejected before any action.
- **PII redaction** (`redact.go`) — the hash chain protects *integrity*, not
  *confidentiality*; this module masks phone/email/name/customer-id at every read
  surface (dashboard, exception list, auditor export).
- **External anchor** (`anchor.go`) — a raw chain can be silently rebuilt by
  someone with write access; this publishes a root hash to an append-only sink
  outside the log, and a rebuilt chain fails the tail/root check.
- **LLM output validation** (`llm.go`) — the LLM never decides, but its copy
  still reaches customers. Injection patterns, `<script>`/`<iframe>`, control
  chars, over-length, internal/localhost URLs, and PII leakage are rejected at the
  boundary.
- **Secrets policy** (`secrets.go`) — fail-closed `requireSecret()` from env only,
  never hard-coded, never printed (`redactSecret()`).
- **Sandbox isolation** (`execution.go`) — `ExecutionMode == 'sandbox'`
  structurally cannot call a live/test-mode charge API; charge-capable flows are
  pure in-process simulations. `/demo`, `/sandbox` all run sandboxed.

**Known gaps — stated honestly (the pitch names these before a judge does):**
- Auth is a *stub* (API-key allow-list), not a real identity/session layer.
- No rate-limiting / replay protection on retry *execution* (charge attempts).
- Webhook body size is not bounded (a giant body is read before the HMAC gate).
- No DPDP data-retention/deletion story for the audit log.
- No anomaly detection watching the policy engine's own behavior.
- Raw Razorpay payloads are **not** consumed directly: `ParseTrustedEvent`
  expects the normalized `{event_id|id, flow|entity.type}` envelope; the
  raw-payload → envelope **adapter is the merchant-side seam** and is a
  documented gap by design (contract tests pin this split).
- The render dashboard (auditor/admin views, live tamper demo) is a listed
  roadmap item, not yet built.
- The webhook secret here is an injected demo value; production uses
  `requireSecret('RAZORPAY_WEBHOOK_SECRET')`.

## Commands

Build and test:

```bash
cd go
export PATH="$HOME/go-toolchain/go/bin:$PATH"   # adjust to your Go install
go build ./...
go vet ./...
go test ./rz/                     # 14 test files: 113 tests + 5 fuzz seed-corpora
go test -run Integration ./rz/    # only the HTTP integration tests
go test -cover ./rz/              # statement coverage
```

Blazor UI (from the repository root):

```bash
dotnet build RazorGateway.slnx
dotnet test  RazorGateway.slnx                                   # 74 tests: unit + integration
dotnet test  RazorGateway.slnx --filter "FullyQualifiedName~Unit"
dotnet test  RazorGateway.slnx --filter "FullyQualifiedName~Integration"
```

## Testing

| Suite | Where | What it proves |
|-------|-------|----------------|
| Go unit | `go/rz/*_test.go` | every named rule, the state machine, hash chain, anchor, redaction, config loader, idempotency |
| Go fuzz | `go/rz/fuzz_test.go` | classify / parse / verify / redact / LLM validation never panic on hostile input |
| Go integration | `go/rz/integration_test.go` | the canonical batch is run into a real audit log and served by the production HTTP handler: auth on every route, role matrix, metrics match the log, redacted exceptions, SSE replay + live push, tamper demo, admin overrides refused by locked rules |
| C# unit | `tests/GatewayUI.Tests/Unit` | order validation, payment + webhook signature checks, webhook idempotency, payment audit hash chain (restart, tamper, concurrency), Go API client error mapping, SSE client de-duplication |
| C# integration | `tests/GatewayUI.Tests/Integration` | the real app in-memory: order / verify / webhook status codes, 1 MB webhook limit, rate limiting, audit file stays a valid chain |

The C# tests never touch the network or real credentials: outbound HTTP is a
stub, secrets are fixed fake values, and audit files live in a temp directory.
CI (`.github/workflows/ci.yml`) runs both stacks, with the Go race detector on.

Native fuzzing (each target also runs its seeds during the normal `go test`
above; extend with `-fuzztime`):

```bash
go test -fuzz=FuzzClassify          -fuzztime=30s ./rz/
go test -fuzz=FuzzParseTrustedEvent -fuzztime=30s ./rz/
go test -fuzz=FuzzVerifyWebhook     -fuzztime=30s ./rz/
go test -fuzz=FuzzRedactPII         -fuzztime=30s ./rz/
go test -fuzz=FuzzValidateLLMCopy   -fuzztime=30s ./rz/
```

Race detection (`-race`) requires a 64-bit C compiler on Windows (the shipped
MinGW is 32-bit and fails at `runtime/cgo`). On a 64-bit toolchain or Linux:

```bash
go test -race ./rz/               # mutex-guarded store + at-most-once claim under real races
```

CLIs (run from `go/` after generation):

```bash
go run ./cmd/gen-events                                        # canonical 60-event batch -> data/flows/
go run ./cmd/gen-events -seed 777 -count 120 -out /tmp/flows   # configurable batch (flows scale proportionally)
go run ./cmd/run-batch                                         # full batch run + metrics + audit table + exceptions
go run ./cmd/run-batch -config tunables.example.json           # thresholds from a compliance-sourced file
go run ./cmd/verify-audit  # verify the tamper-evident hash chain
go run ./cmd/compare-policy# REAL vs NAIVE policy comparison + compliance lift
go run ./cmd/compare-policy -config tunables.example.json
go run ./cmd/prescore      # prevention layer: predict-before-fail report
go run ./cmd/sandbox       # tunable sweep, locked rules invariant
go run ./cmd/security      # security posture demo (webhook/auth/redaction/anchor/LLM/secrets)
go run ./cmd/demo          # batch walkthroughs (mandate_revoked, NPCI window, checkout incentive)
```

## Demo output

`go run ./cmd/run-batch` prints measured results over the 60-event batch:
- recovery rate (`recovered_amount / total_at_risk_amount`),
- cost per recovery (`touches_sent / recovered_count`),
- per-flow breakdown,
- full exception list (escalated / abandoned / waiting) with reasons and rule fired,
- an LLM exception summary for a human reviewer, and
- a hash-chain verification (`✓ chain verified: 188 entries, no tampering detected`).

Measured parity with the original TypeScript run is exact: 188 audit entries,
₹851208.52 recovered of ₹1384523.97 at risk (61.5%), 32 recovered, 81 touches,
65 naive-policy compliance violations.
