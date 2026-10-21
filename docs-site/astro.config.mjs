// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// mcpwn documentation site.
//
// Deploy target: GitHub project Pages at https://moizxsec.github.io/mcpwn/.
// `site` + `base` below drive every generated URL. The #1 failure mode for a
// project Pages site is an internal link/asset that forgets `base`, so:
//   - assets are ESM-imported (Astro rewrites them with `base` + a hash),
//   - the bespoke landing page prefixes links with import.meta.env.BASE_URL,
//   - the TypeDoc tree is copied verbatim from public/api (it uses relative
//     links internally, so it is relocatable under /mcpwn/api/).
//
// The published npm tool is NOT affected by anything here: Astro/Starlight live
// only in docs-site/package.json; the root package stays zero-runtime-deps.
export default defineConfig({
  site: "https://moizxsec.github.io",
  base: "/mcpwn/",
  // Clean directory URLs (/guides/scan/), matching GitHub Pages behaviour.
  trailingSlash: "ignore",
  integrations: [
    starlight({
      title: "mcpwn",
      description:
        "Intercept & tamper proxy for MCP traffic: X-ray and tamper the JSON-RPC between an AI agent and its MCP servers. Burp Suite for AI agents. Authorized testing only.",
      // Dark-first: default to dark, light theme derived in theme.css. The
      // `mcpwn▮` wordmark is the title string styled in theme.css (mono font +
      // block cursor) - a real font beats an SVG with un-embedded text.
      favicon: "/favicon.svg",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/moizxsec/mcpwn",
        },
      ],
      editLink: {
        baseUrl: "https://github.com/moizxsec/mcpwn/edit/main/docs-site/",
      },
      // Self-hosted fonts (no runtime CDN) + the verbatim report.ts palette.
      customCss: [
        "@fontsource/inter/400.css",
        "@fontsource/inter/600.css",
        "@fontsource/inter/700.css",
        "@fontsource/jetbrains-mono/400.css",
        "@fontsource/jetbrains-mono/700.css",
        "./src/styles/theme.css",
      ],
      // Pin code highlighting to a github-dark-based theme (matches the palette).
      expressiveCode: {
        themes: ["github-dark", "github-light"],
        styleOverrides: { borderRadius: "6px" },
      },
      head: [
        {
          tag: "meta",
          attrs: {
            property: "og:image",
            content: "https://moizxsec.github.io/mcpwn/og.svg",
          },
        },
        {
          tag: "meta",
          attrs: { name: "twitter:card", content: "summary_large_image" },
        },
      ],
      sidebar: [
        {
          label: "Start",
          items: [
            { label: "What is mcpwn", slug: "start/what" },
            { label: "Install", slug: "start/install" },
            { label: "Quickstart", slug: "start/quickstart" },
          ],
        },
        {
          label: "Guides",
          items: [
            { label: "Intercept proxy", slug: "guides/proxy" },
            { label: "Wrap & init", slug: "guides/wrap-init" },
            { label: "Tamper rules", slug: "guides/tamper-rules" },
            { label: "Active scan", slug: "guides/scan" },
            { label: "Reports & advisories", slug: "guides/report" },
            { label: "Auditing playbook", slug: "guides/auditing" },
            { label: "Guard mode", slug: "guides/guard" },
            { label: "Transports & CI", slug: "guides/transports-ci" },
            { label: "Config file", slug: "guides/config" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "Threat taxonomy", slug: "threats" },
            { label: "Template gallery", slug: "templates" },
            { label: "DVMCP scoreboard", slug: "dvmcp" },
            {
              label: "API reference",
              link: "/api/",
              attrs: { target: "_blank", rel: "noopener" },
              badge: "TypeDoc",
            },
          ],
        },
        {
          label: "Project",
          items: [
            { label: "Contributing", slug: "project/contributing" },
            { label: "Security policy", slug: "project/security" },
            { label: "Advisory template", slug: "project/advisory-template" },
            { label: "Changelog", slug: "project/changelog" },
          ],
        },
      ],
    }),
  ],
});
