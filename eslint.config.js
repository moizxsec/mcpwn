import js from "@eslint/js";
import tseslint from "typescript-eslint";

/**
 * Flat ESLint config (ESLint 9 + typescript-eslint 8). We lint only the
 * TypeScript source under `src/` — build output, generated API docs, coverage,
 * the JS demo servers/tooling and the JS test files are intentionally excluded.
 */
export default tseslint.config(
  {
    ignores: [
      "dist/",
      "docs/api/",
      "coverage/",
      "node_modules/",
      "examples/",
      "tools/",
      "test/",
    ],
  },
  {
    files: ["src/**/*.ts"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    rules: {
      // JSON-RPC payloads are genuinely dynamic data: every message body is
      // arbitrary JSON we parse, mutate and re-serialize. Typing those as
      // `unknown` would force a cast at every property access and obscure the
      // tamper logic, so `any` is a deliberate, documented choice in this
      // codebase — not a type bug being hidden.
      "@typescript-eslint/no-explicit-any": "off",
      // Keep unused-var detection on, but honour the leading-underscore
      // convention for parameters that only exist to satisfy an interface
      // signature (e.g. a Detector that ignores the findings sink).
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  }
);
