# MCP threat taxonomy

A maintained catalogue of the attack classes that matter for the Model Context
Protocol (MCP), and exactly how **mcpwn** covers each one. This is the reference
doc the other pieces cite: every detector id, template, and Damn-Vulnerable-MCP
(dvmcp) server below is real and shipping.

For each class: **what it is**, a **real-world analogue**, the **mcpwn coverage**
(detector / template / dvmcp server / command), the **CWE**, and **remediation**.
The CWE + CVSS v3.1 scoring for each finding id lives in
[`src/advisory.ts`](../src/advisory.ts) and is emitted per-finding by
`mcpwn advisory` (see below) and in the SARIF rule metadata.

See also:

- the **dvmcp scoreboard** - one intentionally-vulnerable server per class:
  [`examples/dvmcp/README.md`](../examples/dvmcp/README.md)
- the **template gallery** - mcpwn-as-attacker rule-packs:
  [`templates/`](../templates) (`mcpwn templates list`)
- the **detectors** - [`src/detect/linter.ts`](../src/detect/linter.ts),
  [`src/detect/baseline.ts`](../src/detect/baseline.ts),
  [`src/detect/pin.ts`](../src/detect/pin.ts),
  [`src/detect/taint.ts`](../src/detect/taint.ts)
- the **guard firewall** - [`src/guard/guard.ts`](../src/guard/guard.ts)
- the **auditing playbook** - [`docs/AUDITING.md`](./AUDITING.md)
- the **advisory template** - [`docs/ADVISORY_TEMPLATE.md`](./ADVISORY_TEMPLATE.md)

## Turning findings into advisories

Any findings directory (`--findings-out <dir>`) becomes a set of filled CVSS
v3.1 + CWE advisories:

```bash
mcpwn scan --findings-out ./out -- node ./my-server.js
mcpwn advisory ./out -o ./advisories      # one .md per finding
mcpwn advisory ./out -o advisories.md     # one combined document
mcpwn advisory ./out                      # combined document to stdout
```

## Index

| # | Attack class | CWE | Primary mcpwn coverage |
|---|--------------|-----|------------------------|
| 1 | Indirect prompt injection (tool result / resource / prompt) | CWE-74 / CWE-1427 | `tool-poisoning`, `provenance-taint` detectors; `indirect-injection-via-resource` template + dvmcp server |
| 2 | Tool poisoning | CWE-1427 | `tool-poisoning` detector; `tool-poisoning` template + dvmcp server |
| 3 | Tool shadowing / name collision | CWE-706 | `tool-shadowing` detector |
| 4 | Rug pull (tool-definition drift) | CWE-494 | `--baseline` (`tool-added`/`tool-definition-changed`/`tool-removed`), `--pin` (`pin-drift`); `rug-pull-after-calls` template + dvmcp server |
| 5 | Sampling abuse | CWE-1427 | `sampling-abuse` detector; `sampling-abuse` template + dvmcp server |
| 6 | Elicitation phishing | CWE-451 | scanner declines + logs server-initiated requests; guard `warn` |
| 7 | Confused deputy / cross-server | CWE-441 | `provenance-taint`, `tool-shadowing` detectors |
| 8 | Token passthrough | CWE-522 / CWE-200 | `secret-exposure` detector, `--redact` |
| 9 | SSRF in a tool implementation | CWE-918 | `scan --fuzz` (ssrf payloads) + `embedded-url` detector; `ssrf` dvmcp server |
| 10 | Path traversal in a tool implementation | CWE-22 | `scan --fuzz` (path-traversal payloads) + `secret-exposure`; `path-traversal` dvmcp server |
| 11 | OS command injection in a tool implementation | CWE-78 | `scan --fuzz` (command-injection payloads) + `dangerous-tool`/`secret-exposure`; `command-injection` dvmcp server |
| 12 | Data exfiltration (out-of-band URL) | CWE-200 | `embedded-url` detector; `exfil-url` template + dvmcp server |
| 13 | Invisible-unicode smuggling | CWE-1427 | `invisible-unicode` detector; guard `sanitize` |
| 14 | Provenance / injection -> action chaining | CWE-1427 / CWE-77 | `provenance-taint` detector (`--taint`) |
| 15 | Mislabelled capability (readOnlyHint lie) | CWE-807 | `annotation-mismatch` detector |

---

## 1. Indirect prompt injection (tool result / resource / prompt)

**What:** attacker-controlled text that reaches the model *through data the agent
ingests* - a `tools/call` result, a `resources/read` body, or a `prompts/get`
message - rather than through the user's prompt. The model reads it as
instructions.

**Real-world analogue:** stored XSS, but the "browser" is an LLM: the payload
lives in otherwise-trusted content and executes when rendered into the model's
context.

**mcpwn coverage:** the `tool-poisoning` detector
(`InjectionMarkerInDescriptionDetector`) scans *every* agent-bound surface, not
just tool descriptions; `provenance-taint` (`--taint`) proves the content later
steers an action (see #14). Template:
[`templates/indirect-injection-via-resource.json`](../templates/indirect-injection-via-resource.json);
dvmcp server: `examples/dvmcp/indirect-injection-via-resource.mjs`
(`mcpwn scan -- node examples/dvmcp/indirect-injection-via-resource.mjs`).

**CWE:** CWE-74 (Injection) / CWE-1427 (LLM prompt injection).

**Remediation:** treat all server-supplied content as untrusted *data*, never
instructions. Fence tool output in the host, strip/escape control sequences, and
require explicit confirmation for any action derived from tool output.

## 2. Tool poisoning

**What:** a malicious server embeds instructions in a tool's **metadata** (its
`description`, parameter docs, or annotations) so the model obeys them the moment
it sees the tool list - no call required.

**Real-world analogue:** a poisoned README / man page that tells whoever reads it
to run a dangerous command.

**mcpwn coverage:** `tool-poisoning` detector on `tools/list`. Template:
[`templates/tool-poisoning.json`](../templates/tool-poisoning.json); dvmcp
server: `examples/dvmcp/tool-poisoning.mjs`
(`mcpwn scan -- node examples/dvmcp/tool-poisoning.mjs`).

**CWE:** CWE-1427.

**Remediation:** render tool metadata as inert text in the host; never feed
descriptions to the model as directives; review tool manifests before approval.

## 3. Tool shadowing / name collision

**What:** two advertised tools share a name (ambiguous/hijackable), or a server
tool is named after a trusted client built-in (`bash`, `web_fetch`, …) so the
agent routes a privileged call to the impostor.

**Real-world analogue:** PATH hijacking / DLL search-order abuse - a look-alike
binary earlier in the resolution order wins.

**mcpwn coverage:** `tool-shadowing` detector (duplicate names = high;
built-in collision = medium).

**CWE:** CWE-706 (Incorrectly-Resolved Name or Reference); see also CWE-441.

**Remediation:** reject duplicate tool names; namespace server tools; never allow
a server tool to shadow a client built-in.

## 4. Rug pull (tool-definition drift)

**What:** a server serves a benign surface during approval, then silently mutates
a description/schema or adds a privileged tool on a later listing - after the
user has built trust.

**Real-world analogue:** a browser extension that ships clean, then pushes a
malicious auto-update; dependency "protestware".

**mcpwn coverage:** `--baseline` diffs each `tools/list` against a captured
snapshot (`tool-added` / `tool-definition-changed` / `tool-removed`). `--pin`
(`mcpwn pin capture`) is the CI-grade, cross-session cousin: it hashes the whole
advertised surface (tools + resources + prompts) into a committed `mcpwn.lock`
and reports any later drift as `pin-drift` (high). Template:
[`templates/rug-pull-after-calls.json`](../templates/rug-pull-after-calls.json);
dvmcp server: `examples/dvmcp/rug-pull.mjs`.

**CWE:** CWE-494 (Download of Code Without Integrity Check).

**Remediation:** pin the advertised surface and re-approve on any change; commit
`mcpwn.lock` and gate CI on it.

## 5. Sampling abuse

**What:** a server issues a `sampling/createMessage` request, asking the client
to run an LLM completion on its behalf with a server-authored prompt - letting
the server drive the user's model directly.

**Real-world analogue:** SSRF for LLMs - the server makes *your* model perform
work (and spend tokens) under its direction.

**mcpwn coverage:** `sampling-abuse` detector records every server-initiated
`sampling/createMessage`; the malicious prompt text also trips `tool-poisoning`.
Template: [`templates/sampling-abuse.json`](../templates/sampling-abuse.json);
dvmcp server: `examples/dvmcp/sampling-abuse.mjs`. The scanner *declines* the
request, so nothing blocks.

**CWE:** CWE-1427 (prompt injection via sampling); see also CWE-441.

**Remediation:** require explicit user consent for server-initiated sampling;
show the server-supplied prompt; rate-limit and scope it.

## 6. Elicitation phishing

**What:** a server uses MCP *elicitation* (a server-initiated request for user
input) to phish - crafting a convincing prompt that coaxes the user into
revealing a secret or approving an action.

**Real-world analogue:** a phishing dialog that impersonates a trusted app's
"please re-enter your password" prompt.

**mcpwn coverage:** `mcpwn scan` declines and logs all server-initiated requests
(including elicitation), so they surface in the session log; the guard can
`warn` on injection phrasing inside them. A dedicated elicitation detector is on
the roadmap.

**CWE:** CWE-451 (User Interface Misrepresentation of Critical Information).

**Remediation:** clearly attribute elicitation prompts to the (untrusted) server
in the UI; never auto-answer; never let a server request credentials.

## 7. Confused deputy / cross-server

**What:** a server induces the agent to use its standing authority - or data from
one server - to act against *another* server or resource the server itself could
not reach.

**Real-world analogue:** the classic confused-deputy (CSRF, SSRF): a less-
privileged actor tricks a more-privileged one into misusing its rights.

**mcpwn coverage:** `provenance-taint` flags content from one (untrusted) message
flowing into a privileged call (#14); `tool-shadowing` flags the impersonation
path. A full multi-server correlation view is on the roadmap.

**CWE:** CWE-441 (Unintended Proxy or Intermediary - "Confused Deputy").

**Remediation:** scope each server's authority narrowly; don't let output from
one server auto-drive calls to another; require per-action confirmation.

## 8. Token passthrough

**What:** a server passes the client's/agent's access token straight through to an
upstream API (an explicit MCP anti-pattern), or otherwise relays credentials it
should never see or forward.

**Real-world analogue:** an OAuth "confused deputy" / token-relay where a
middle-man forwards a bearer token beyond its intended audience.

**mcpwn coverage:** `secret-exposure` flags known credential formats anywhere in
agent-bound traffic; `--redact` masks them in logs. Watching both directions in
the proxy shows a token leaving the client and reappearing upstream.

**CWE:** CWE-522 (Insufficiently Protected Credentials); see also CWE-200.

**Remediation:** never pass client tokens through a server; mint audience-scoped
tokens per hop; validate the `aud` claim.

## 9. SSRF in a tool implementation

**What:** a tool that fetches a URL does so with no allowlist or
internal-target block, so an attacker (or a coerced agent) reaches cloud metadata
(`169.254.169.254`), loopback services, or internal hosts.

**Real-world analogue:** textbook SSRF against a web app's URL-fetch feature.

**mcpwn coverage:** `scan --fuzz` cycles the bundled `ssrf` payload library into
string parameters; `embedded-url` flags link-local / raw-IP / out-of-band hosts
in the result as high. dvmcp server: `examples/dvmcp/ssrf.mjs`
(`mcpwn scan --fuzz -- node examples/dvmcp/ssrf.mjs`). Hand-craft vectors with
`-i` per [docs/AUDITING.md](./AUDITING.md).

**CWE:** CWE-918 (SSRF).

**Remediation:** allowlist destinations; block private/link-local ranges *after*
DNS resolution; restrict schemes; beware TOCTOU between check and fetch.

## 10. Path traversal in a tool implementation

**What:** a tool that takes a path joins caller input onto a base dir with no
normalisation or containment check, letting `../../etc/passwd`-style input escape.

**Real-world analogue:** directory traversal in any file-serving endpoint.

**mcpwn coverage:** `scan --fuzz` cycles the `path-traversal` payloads; the
escape returns sensitive content whose secret trips `secret-exposure`. dvmcp
server: `examples/dvmcp/path-traversal.mjs`.

**CWE:** CWE-22 (Path Traversal).

**Remediation:** resolve to absolute, check `resolved.startsWith(allowedDir +
sep)` (note the trailing separator), reject null bytes, and `realpath` to defeat
symlinks before access.

## 11. OS command injection in a tool implementation

**What:** a tool interpolates caller input into a shell string (`run_shell`, git/
grep wrappers), allowing `; id`, `$(…)`, backticks to execute.

**Real-world analogue:** command injection in any system() wrapper.

**mcpwn coverage:** `dangerous-tool` flags high-impact tool names
(`exec`/`shell`/…) from a plain `scan`; `--fuzz` with `command-injection`
payloads demonstrates the leak (`secret-exposure`). dvmcp server:
`examples/dvmcp/command-injection.mjs`.

**CWE:** CWE-78 (OS Command Injection).

**Remediation:** never build shell strings from input; use argv-array execution
with no shell; strict allowlists for subcommands and flags.

## 12. Data exfiltration (out-of-band URL)

**What:** a tool result or resource embeds an out-of-band URL (a collaborator /
webhook / paste host) that an auto-fetching agent will follow, leaking any data
appended to it.

**Real-world analogue:** a tracking pixel / beacon URL that fires on render.

**mcpwn coverage:** `embedded-url` flags out-of-band collaborator hosts and raw
IPs as high. Template: [`templates/exfil-url.json`](../templates/exfil-url.json);
dvmcp server: `examples/dvmcp/exfil-url.mjs`.

**CWE:** CWE-200 (Exposure of Sensitive Information); see also CWE-918.

**Remediation:** never auto-fetch URLs found in tool output; treat server-
supplied links as untrusted; strip or sandbox them (the guard removes known
exfil hosts).

## 13. Invisible-unicode smuggling

**What:** zero-width, soft-hyphen, bidi-control, or Unicode-Tag code points hide
instructions in agent-bound text: invisible to a human reviewer, read by the
model (ASCII smuggling / hidden prompt injection).

**Real-world analogue:** homoglyph / zero-width steganography in phishing and
plagiarism-evasion.

**mcpwn coverage:** `invisible-unicode` detector (high when Unicode-Tag chars are
present - no legitimate use - else medium); the guard `sanitize` action strips
them before the agent sees them.

**CWE:** CWE-1427 (hidden-instruction prompt injection); see also CWE-150
(control-sequence neutralisation).

**Remediation:** strip non-printable / zero-width / tag characters from all
server-supplied text before it reaches the model.

## 14. Provenance / injection -> action chaining

**What:** the kill chain that makes indirect injection *real*: text that
originated from an untrusted tool result / resource later reappears inside a
privileged `tools/call` argument - attacker content from a source message is now
steering a sink call.

**Real-world analogue:** a taint flow from an untrusted source to a dangerous
sink (SQLi/SSRF taint analysis), applied to agent behaviour.

**mcpwn coverage:** `provenance-taint` detector (`--taint`): a bounded, read-only
substring taint index that raises a high finding when a tainted token flows into
a later call argument.

**CWE:** CWE-1427 (indirect prompt injection); see also CWE-77.

**Remediation:** don't let the agent pass server-supplied text verbatim into
further tool calls; require explicit confirmation for actions derived from tool
output.

## 15. Mislabelled capability (readOnlyHint lie)

**What:** a mutating tool (write/delete/execute) is annotated `readOnlyHint:true`.
Clients often auto-approve "read-only" tools, so the mislabelled tool runs without
the user's confirmation.

**Real-world analogue:** an app requesting a benign permission scope while
performing privileged actions behind it.

**mcpwn coverage:** `annotation-mismatch` detector on `tools/list` (high).

**CWE:** CWE-807 (Reliance on Untrusted Inputs in a Security Decision); see also
CWE-862.

**Remediation:** never trust server-supplied safety annotations for an
auto-approve decision; set annotations honestly server-side; gate mutating tools
behind confirmation regardless of the hint.

---

## Contributing

Found a class mcpwn should cover, or a better CWE/remediation? Open a PR - add the
class here, wire a detector or template, and (ideally) a dvmcp server so the
scoreboard can grade it. See [CONTRIBUTING.md](../CONTRIBUTING.md).
