// @ts-check
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**"]
  },
  ...tseslint.configs.recommended,
  {
    rules: {
      // No `any` — the security guard depends on precise types.
      "@typescript-eslint/no-explicit-any": "error",
      "no-console": ["warn", { allow: ["error"] }] // stdout is reserved for MCP traffic
    }
  },
  {
    // Return types are a TypeScript concern; plain-JS tooling scripts can't declare them.
    files: ["**/*.ts"],
    rules: {
      "@typescript-eslint/explicit-function-return-type": [
        "warn",
        { allowExpressions: true }
      ]
    }
  }
);
