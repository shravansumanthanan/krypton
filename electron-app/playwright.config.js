const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testMatch: '**/*.spec.js',
  use: {
    trace: 'on-first-retry',
  },
});
