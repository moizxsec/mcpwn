// One-shot generator: port the repo's existing Markdown into Starlight content.
//
// It prepends Starlight frontmatter, drops the leading H1 (Starlight renders the
// frontmatter title as the page H1), and rewrites every link so it works under
// the project-Pages base (/mcpwn/): links into src/ and other un-ported repo
// files go to GitHub; links between ported docs become internal /mcpwn/ slugs.
//
// Run once from the repo root: `node docs-site/scripts/port-docs.mjs`.
// The emitted .md files are the source of truth afterwards.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const OUT = join(ROOT, "docs-site", "src", "content", "docs");
const GH = "https://github.com/moizxsec/mcpwn/blob/main";
const GHT = "https://github.com/moizxsec/mcpwn/tree/main";

/** Rewrite one markdown link target to be valid on the deployed site. */
function rewriteTarget(t) {
  if (/^(https?:|mailto:|#)/.test(t)) return t; // external / anchor — leave
  const raw = t.replace(/^\.\//, "").replace(/^(\.\.\/)+/, ""); // strip ./ ../

  // Cross-references between ported docs -> internal base-prefixed slugs.
  const internal = {
    "docs/THREATS.md": "/mcpwn/threats/",
    "THREATS.md": "/mcpwn/threats/",
    "docs/AUDITING.md": "/mcpwn/guides/auditing/",
    "AUDITING.md": "/mcpwn/guides/auditing/",
    "docs/ADVISORY_TEMPLATE.md": "/mcpwn/project/advisory-template/",
    "ADVISORY_TEMPLATE.md": "/mcpwn/project/advisory-template/",
    "SECURITY.md": "/mcpwn/project/security/",
    "CONTRIBUTING.md": "/mcpwn/project/contributing/",
    "CHANGELOG.md": "/mcpwn/project/changelog/",
    "README.md": "/mcpwn/",
    "examples/dvmcp/README.md": "/mcpwn/dvmcp/",
    "templates": "/mcpwn/templates/",
    "templates/": "/mcpwn/templates/",
    "../templates": "/mcpwn/templates/",
  };
  if (internal[raw]) return internal[raw];
  if (internal[t]) return internal[t];

  // A specific template JSON file -> GitHub blob.
  if (/^templates\/.+\.json$/.test(raw)) return `${GH}/${raw}`;
  // Source files and other code -> GitHub blob.
  if (/^(src|examples|tools|test|schema)\//.test(raw)) return `${GH}/${raw}`;
  if (raw === "LICENSE" || raw === "action.yml") return `${GH}/${raw}`;
  // Directory references -> GitHub tree.
  if (raw === "payloads" || raw === "payloads/") return `${GHT}/payloads`;
  if (raw === "examples" || raw === "examples/") return `${GHT}/examples`;
  return t; // leave anything we didn't match (surfaced in review)
}

function port(srcRel, outRel, title, description) {
  const src = readFileSync(join(ROOT, srcRel), "utf8");
  const lines = src.split("\n");
  // Drop the leading H1 (and a following blank line).
  let i = 0;
  while (i < lines.length && lines[i].trim() === "") i++;
  if (lines[i] && /^#\s+/.test(lines[i])) {
    i++;
    if (lines[i] && lines[i].trim() === "") i++;
  }
  let body = lines.slice(i).join("\n");

  // Rewrite markdown links [text](target) — but not image/code content.
  body = body.replace(/(\]\()([^)\s]+)(\s+"[^"]*")?(\))/g, (m, a, tgt, tit, c) => {
    return a + rewriteTarget(tgt) + (tit || "") + c;
  });

  const esc = (s) => s.replace(/"/g, '\\"');
  const fm = `---\ntitle: "${esc(title)}"\ndescription: "${esc(description)}"\n---\n\n`;
  const outPath = join(OUT, outRel);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, fm + body.replace(/\s+$/, "") + "\n");
  console.log("wrote", outRel);
}

port(
  "docs/THREATS.md",
  "threats.md",
  "MCP threat taxonomy",
  "Every MCP attack class mcpwn covers — what it is, its CWE, the detector/template/dvmcp server that owns it, and the fix.",
);
port(
  "docs/AUDITING.md",
  "guides/auditing.md",
  "Auditing playbook",
  "A practical, repeatable workflow for finding real vulnerabilities in MCP servers with mcpwn.",
);
port(
  "examples/dvmcp/README.md",
  "dvmcp.md",
  "DVMCP — Damn Vulnerable MCP",
  "A graded set of intentionally-vulnerable local MCP servers — one per attack class — each paired with the mcpwn command that owns it.",
);
port(
  "CONTRIBUTING.md",
  "project/contributing.md",
  "Contributing",
  "Project layout, invariants, and how to add a new rule kind or transport.",
);
port(
  "SECURITY.md",
  "project/security.md",
  "Security policy",
  "Intended use, how to report a vulnerability in mcpwn, and responsible disclosure of findings made with mcpwn.",
);
port(
  "docs/ADVISORY_TEMPLATE.md",
  "project/advisory-template.md",
  "Advisory template",
  "A fill-in security-advisory template for a vulnerability found with mcpwn.",
);
port(
  "CHANGELOG.md",
  "project/changelog.md",
  "Changelog",
  "All notable changes to mcpwn, Keep-a-Changelog format.",
);
