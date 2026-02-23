# AI-Agentic Nmap — Product design & plan

**Purpose:** Architectural intent, philosophy, and product-level design. **Implementation details** (state model, action menu, schemas, phases, tasks) live in [implementation_design.md](implementation_design.md).

---

## 1. Architectural intent and philosophy (canonical)

This section defines what we are building and what we are not. It is the reference for alignment.

### What we are building

**We are building an AI-Agentic Nmap system.**

- This is **NOT** a simple automation wrapper around Nmap.
- This is **NOT** an LLM that generates raw shell commands.

**Core intent:** A **bounded, policy-controlled reconnaissance agent** where:

1. **Nmap execution is controlled entirely by our Python engine.** The engine builds and runs every command; the AI never constructs shell or nmap CLI strings for execution.
2. **Closed loop:** Observe → Reason → Decide → Act → Evaluate → Repeat.
3. **AI role:** Reasoning assistant or bounded decision-maker. It suggests or selects the *next logical action* from a **predefined action space**; it does not invent commands.
4. **AI never outputs raw shell commands.** It outputs a *choice* (e.g. an action ID or structured action descriptor); the engine maps that to a safe, allowlisted nmap invocation.
5. **All execution is protected by strict guardrails**, especially when sudo is used.

### Philosophy: AI as junior security analyst

We treat the AI as a **junior security analyst**:

- It **interprets** scan results.
- It **explains** what is happening (when in a mode that supports explanation).
- It **suggests** the next logical action.
- It **must choose only from a predefined action space** (e.g. “run discovery”, “run port scan 1–100”, “run service detection”, “wait”, “done”). No free-form flags or commands.
- It operates under **strict scope, timing, and safety policies** enforced by the engine.

**The Python engine:**

- Owns **target validation** and **scope enforcement**.
- Owns **timing caps**, **port caps**, and **script allowlists** (e.g. no NSE unless explicitly allowlisted).
- Owns **command construction** and **execution** (only allowlisted nmap invocations).
- Owns **stop conditions** and **budget tracking**.

**The AI does NOT:**

- Expand scope beyond the given target.
- Generate arbitrary Nmap flags.
- Escalate intensity without justification (or outside policy).
- Bypass guardrails.
- Execute anything directly.

### Agentic definition (when we call it “agentic”)

The system is **agentic** when:

- It **adapts** scan strategy based on observed results.
- It can **skip** unnecessary steps.
- It can **stop early** when marginal gain is low.
- It can **prioritize** high-value services.
- It operates under a **defined objective** (e.g. coverage or exploitability signal).
- It **maintains state** between iterations.

### Modes of operation

1. **Assistant mode**  
   AI summarizes scan output and **suggests** the next action. **Human confirms** before execution.

2. **Bounded agent mode**  
   AI **selects** the next action from the predefined action menu. Engine **validates and executes automatically** (within guardrails).

### Primary objective (v1)

Build a **safe, bounded, adaptive scan planner for a single target** (one IP/hostname). Focus on:

- Clean **state tracking**
- Safe **decision loop**
- **Controlled action menu**
- **Strict guardrails**

### What we are NOT building

- Autonomous offensive exploitation.
- A command-generating LLM shell executor.
- Internet-wide or unbounded scanner.
- Unbounded reconnaissance engine.

**Goal:** Disciplined, adaptive, policy-driven reconnaissance.

---

## 2. Alignment with previous design doc

The following table maps the canonical intent above to the earlier design and confirms alignment.

| Canonical intent | Previous design | Aligned? |
|------------------|-----------------|----------|
| Nmap execution only by Python engine | “We execute only validated nmap” | Yes |
| Closed loop Observe → … → Act → Evaluate → Repeat | “observe state → agent decides → we validate & execute → update state” | Yes (same loop; “Reason/Decide” = agent, “Act” = engine, “Evaluate” = state update) |
| AI never outputs raw shell commands | “AI outputs one action (e.g. RUN with params)”; guardrails parse and engine builds command | **Refine:** Action should be from a **predefined menu** (e.g. action IDs or structured descriptors), not free-form “RUN target=X scan_type=-sn”. Engine maps choice → allowlisted nmap. |
| Predefined action space | “Allowed actions (RUN with allowlisted params)” | **Refine:** Explicit **action menu** (fixed set of choices), not “any RUN with allowlisted flags”. Agent picks from menu; engine maps to command. |
| Python owns scope, timing, caps, command construction, execution | Guardrails: scope, command, script, budget, parse, sudo, drift | Yes |
| Assistant vs Bounded Agent mode | Not previously called out | **Add:** Assistant = suggest + human confirm; Bounded agent = auto-execute after validation. |
| v1: single target, safe bounded planner | “Single target + nmap-only for v1” | Yes |
| Not automation wrapper, not shell executor | “Not a fixed script; yes agent with goal + state” | Yes |

**Refinements to carry forward:**

- **Action model:** Define an explicit **action menu**. **First action is always host reachability** (“ping” / `-sn`); then e.g. port_scan_*, service_detect, os_fingerprint, wait, done. Agent selects from this menu; engine maps choice → single, allowlisted nmap invocation. No free-form commands from the AI.
- **Modes:** Support (or design for) both **Assistant** (suggest → human confirm) and **Bounded agent** (select → engine executes). v1 can implement one mode first.

---

## 3. Core design (aligned)

### 3.1 Loop (canonical wording)

**Observe** → **Reason** → **Decide** → **Act** → **Evaluate** → **Repeat**

- **Observe:** Engine provides state (target, **host reachability first** — responded or not; then host status, ports, services, scans run, goal progress).
- **Reason / Decide:** AI interprets state and chooses (or suggests) one action from the **predefined action menu**.
- **Act:** Engine validates the choice, maps it to an allowlisted nmap command (or wait/done), and executes. No shell from AI.
- **Evaluate:** Engine updates state from nmap output (or wait/done).
- **Repeat** until stop condition (goal met, DONE, or budget).

### 3.2 Who owns what

| Concern | Owner |
|--------|--------|
| Target validation, scope | Python engine |
| Timing caps, port caps, script allowlist | Python engine |
| Action menu (allowed choices) | Python engine (defined); AI selects from it |
| Command construction and execution | Python engine only |
| Stop conditions, budget | Python engine |
| Interpreting results, suggesting/choosing next action | AI (bounded to menu) |

### 3.3 State and action (to be detailed in Phase 1)

- **State:** Single representation of “what we know” (target, host, ports, services, OS, scans run, goal progress). Owned and updated by the engine.
- **Action menu:** Predefined set of actions (e.g. host_reachability, port_scan ranges, service_detect, os_fingerprint, wait, done). Agent output = one choice from this set (or a suggestion in Assistant mode). Engine maps choice → one safe nmap call (or wait/done).

### 3.4 First action: host reachability (“ping”), then build the loop

**First action is always host reachability:** check if the host responds (e.g. nmap `-sn` host discovery, or equivalent). Until we know the host is reachable, we don’t proceed to port scans or service detection.

- **If the host responds:** State is updated to “host up”. We are sure it’s up; the loop can then offer port-scan and later actions. AI can choose next (e.g. port_scan_1_100, service_detect, etc.) based on state and goal.
- **If the host does not respond:** State reflects “no response” (or “down” / “filtered” depending on what we infer). There can be other reasons: firewall, wrong IP, host actually down, network issue. The **decision loop** handles this: the AI sees “host did not respond” in state and can choose e.g. `done` (give up), `wait` (retry later), or we can add a limited retry policy in the engine. We do not assume “no response = down” blindly; we represent it in state and let the agent (and policy) reason about it.

**Building the decision loop gradually:**

- Start with a **minimal action menu**: e.g. `host_reachability` (first step), `done`, `wait`. State is minimal: target, reachability result (responded / no response).
- Once host reachability is in place and state is clear, **add the next actions** (e.g. port scan ranges, then service detection, then OS fingerprint). The loop stays the same: Observe (state) → Reason → Decide (action from menu) → Act (engine runs the mapped command) → Evaluate (update state) → Repeat.
- Each new action adds to the menu and possibly to the state (e.g. “open ports”, “services”). The AI always chooses only from the current menu; the engine always validates and maps to a single allowlisted operation.

So: **first action = host reachability (“ping”); if response → host up → continue; if no response → state says so and the loop decides next. Build the rest of the decision loop step by step.**

---

## 4. AI response format (product decision)

**Decision:** The AI responds with **structured JSON** only: required **action_id** (from the action menu), optional **reason** (for Assistant mode and audit). The engine validates and maps `action_id` to a command; it never parses free-form commands or nmap flags from the AI.

**Rationale:** Fits the action menu, simplifies guardrails, enables validation and audit. The AI must not include raw shell, nmap flags, or target in the response.

**Schema, parsing rules, and reject conditions:** See [implementation_design.md §4](implementation_design.md#4-ai-response-format-implementation).

---

## 5. Implementation: where to look

All implementation-related content is in **[implementation_design.md](implementation_design.md)**:

- **State model** (fields, serialization for LLM, goal_achieved)
- **Action menu** (action_id list and engine → nmap mapping)
- **AI response** (JSON schema, parsing steps, reject conditions)
- **Guardrails** (where each is enforced, how)
- **Loop** (step-by-step implementation)
- **Phases and tasks** (Phase 0–4 with checkboxes)
- **Config** (proposed keys and sources)
- **File / module layout** (suggested structure)

This document (PRODUCT_DESIGN.md) does not define implementation details.

---

## 6. Summary

- **Aligned** with: bounded agent, Python-owned execution, closed loop, strict guardrails, no raw shell from AI, single-target v1, “not automation / not shell executor”.
- **Refinements:** Explicit **action menu** (agent selects from menu; engine maps to command). Explicit **Assistant vs Bounded agent** modes. AI never outputs runnable shell or free-form nmap strings; it outputs a **choice** from the menu.
- **AI response format:** **Structured JSON** — required `action_id` (from action menu), optional `reason`. Engine validates and maps `action_id` to command; no parsing of free-form commands.
- **First action:** Always **host reachability** (“ping” / check if host responds). If response → host up → continue; if no response → state reflects it and the decision loop decides next (done, wait, retry). Build the rest of the loop gradually (minimal menu first, then add port scans, service detection, OS, etc.).
- **No implementation** in this document; it defines architectural intent and philosophy only.
