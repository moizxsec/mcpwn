# Auditing MCP servers with mcpwn

A practical playbook for finding real vulnerabilities in MCP servers using
mcpwn. Each recipe maps a threat class to a concrete, repeatable workflow.

> For the full catalogue of MCP attack classes - each with its CWE, the mcpwn
> detector/template/[dvmcp](../examples/dvmcp/README.md) server that covers it,
> and remediation - see the **[MCP threat taxonomy (docs/THREATS.md)](./THREATS.md)**.
> Turn any findings dir into CVSS v3.1 + CWE advisories with
> `mcpwn advisory <findings-dir> -o <dir>`.

> **Authorized testing only.** Run servers you own or are explicitly allowed
> to assess. The cleanest legal footing is to `npx`/run the open-source server
> **locally on your own machine** - you own that execution - and disclose any
> findings responsibly (see [ADVISORY_TEMPLATE.md](./ADVISORY_TEMPLATE.md)).

## Setup

Wrap the target server with mcpwn and drive it with any MCP client (or the
demo agent). Start passive to learn the surface:

```bash
mcpwn -v -l session.jsonl -- npx -y <target-mcp-server> [args...]
```

Then enumerate: every `tools/list`, `resources/list`, and `prompts/list`
response tells you the attack surface and the input schemas you can abuse.

---

## 1. Server-side input flaws (the highest-value bugs)

These are real, exploitable CVEs - path traversal, SSRF, command injection,
IDOR - reachable through `tools/call` **arguments**. mcpwn is the harness for
crafting them; use `-i` to hold a `tools/call` and hand-edit `arguments`.

### Path traversal

For any tool that takes a path/filename, hold the request and try:

```
../../../../etc/passwd
..\..\..\..\windows\win.ini
/etc/passwd
file:///etc/passwd
%2e%2e%2f%2e%2e%2fetc%2fpasswd        # if the server URL-decodes
/proc/self/environ                     # secrets in env
a/../../../../etc/passwd               # defeats naive prefix checks
```

**What a hardened server does (verified against `@modelcontextprotocol/server-filesystem`):**
normalizes + resolves to absolute, checks `resolved.startsWith(allowedDir + sep)`
(note the trailing separator - without it, `/allowed-evil` bypasses `/allowed`),
rejects null bytes, and calls `fs.realpath` to resolve **symlinks** before
access. If a server skips any of these - especially the trailing-separator
check or the realpath/symlink step - it is likely vulnerable.

### SSRF

For any tool that fetches a URL (`fetch`, `http_get`, web tools), hold and try:

```
http://169.254.169.254/latest/meta-data/        # cloud metadata
http://localhost:6379/                            # internal services
http://[::1]:22/
file:///etc/passwd                                # scheme confusion
http://127.0.0.1:80@evil.test/                    # parser confusion
```

A safe server blocks private/link-local ranges *after* DNS resolution and
restricts schemes. Check for TOCTOU: does it resolve DNS once for the check
and again for the fetch?

### Command / argument injection

For tools that shell out (git, grep, build tools):

```
; id ;
$(id)
`id`
--output=/tmp/pwned
-- ; rm -rf (dry-run only on your own box)
```

---

## 2. Indirect prompt injection via tool results

The signature mcpwn workflow. Use a rule to inject attacker text into the
result the agent ingests, then observe whether the agent acts on it.

```bash
mcpwn -r examples/attack-inject.json -- npx -y <target>
```

See `payloads/prompt-injection.txt` for a seed wordlist (or `mcpwn payloads show
prompt-injection`). The finding
is **"the agent obeys instructions found in tool output"** - demonstrate it by
getting the agent to call a sensitive tool it shouldn't.

## 3. Tool poisoning

Hold a `tools/list` response and inject instructions into a tool's
`description` (the `poisonDescription` action). Tests whether the host renders
or the model obeys hidden directives in tool metadata.

## 4. Rug pull

Serve a benign `tools/list` during approval, then mutate it mid-session with a
`matchReplace` rule so the live definition differs from what the user approved.

## 5. Sampling abuse (servers that use `sampling/createMessage`)

Watch for **server→client** `sampling/createMessage` requests. Hold and edit
them to test whether the host blindly forwards server-authored prompts into
the user's LLM.

---

## First audit log

| Target | Version | Result |
| --- | --- | --- |
| `@modelcontextprotocol/server-filesystem` | 2026.1.14 | No traversal/symlink escape via the vectors above - validation uses trailing-separator prefix check + `fs.realpath`. Hardened. |

Contributions of further audits (positive or negative) are welcome - negative
results are valuable too: they document what's already safe.
