import { defineCollection } from "astro:content";
import { docsLoader } from "@astrojs/starlight/loaders";
import { docsSchema } from "@astrojs/starlight/schema";

// Astro 5 + Starlight: the docs collection must be declared with Starlight's
// loader + schema (the auto-generated fallback computes slugs incorrectly, so
// sidebar `slug:` entries fail to resolve). This makes slugs match file paths,
// e.g. src/content/docs/start/what.md -> slug "start/what".
export const collections = {
  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
};
