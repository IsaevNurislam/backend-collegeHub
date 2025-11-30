export default [
  {
    languageOptions: {
      globals: {
        console: true,
        process: true,
        Buffer: true,
        setTimeout: true,
        setInterval: true,
        clearTimeout: true,
        clearInterval: true
      },
      ecmaVersion: 2020,
      sourceType: 'module'
    },
    rules: {
      'no-unused-vars': 'warn',
      'no-console': 'off'
    }
  }
];
