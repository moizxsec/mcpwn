---
title: Config file
description: Commit a baseline invocation instead of retyping flags - mcpwn auto-loads an mcpwn.config.json next to your server. Precedence is defaults < config < CLI flags.
---

Commit a baseline invocation instead of retyping flags. Drop an
`mcpwn.config.json` next to your server and mcpwn auto-loads it (opt out with
`--no-auto-config`, or point elsewhere with `--config <file>`). Precedence is
**defaults < config < CLI flags**, so a flag always wins.

```jsonc
{
  "$schema": "./schema/config.schema.json",
  "rules": ["attack.json"],
  "scope": { "methods": ["tools/*"], "direction": "s2c" },
  "redact": true,
  "findingsOut": "./out",
  "failOn": "high"
}
```

The config schema lives at
[`schema/config.schema.json`](https://github.com/moizxsec/mcpwn/blob/main/schema/config.schema.json).
`mcpwn init` drops a starter config for you (see [Wrap &
init](/mcpwn/guides/wrap-init/)).
