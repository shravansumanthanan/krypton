import js from "@eslint/js";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";
import globals from "globals";

export default [
  js.configs.recommended,
  eslintPluginPrettierRecommended,
  {
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: "module",
      globals: {
        ...globals.node,
        ...globals.browser,
        DOMPurify: "readonly",
      },
    },
    rules: {
      "no-unused-vars": ["warn", { caughtErrors: "none" }],
      "no-console": "warn",
      "no-empty": ["error", { allowEmptyCatch: true }],
    },
  },
  // ── Jest test files ──────────────────────────────────────
  {
    files: ["tests/**/*.js", "tests/**/*.test.js"],
    languageOptions: {
      globals: {
        ...globals.node,
        describe: "readonly",
        test: "readonly",
        it: "readonly",
        expect: "readonly",
        beforeAll: "readonly",
        afterAll: "readonly",
        beforeEach: "readonly",
        afterEach: "readonly",
        jest: "readonly",
      },
    },
    rules: {
      "no-console": "off",
    },
  },
];
