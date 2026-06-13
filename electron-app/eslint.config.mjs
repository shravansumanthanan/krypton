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
        DOMPurify: "readonly"
      }
    },
    rules: {
      "no-unused-vars": ["warn", { "caughtErrors": "none" }],
      "no-console": "warn",
      "no-empty": ["error", { "allowEmptyCatch": true }]
    }
  }
];
