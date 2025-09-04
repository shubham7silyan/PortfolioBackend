module.exports = {
    env: {
        browser: false,
        commonjs: true,
        es2021: true,
        node: true
    },
    extends: [
        'eslint:recommended'
    ],
    parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module'
    },
    rules: {
        'indent': ['error', 4],
        'linebreak-style': 'off',
        'quotes': ['error', 'single'],
        'semi': ['error', 'always'],
        'no-unused-vars': ['warn', { 'argsIgnorePattern': '^_' }],
        'no-console': 'off',
        'no-undef': 'error',
        'no-trailing-spaces': 'warn',
        'eol-last': 'warn',
        'comma-dangle': ['error', 'never'],
        'object-curly-spacing': ['error', 'always'],
        'array-bracket-spacing': ['error', 'never'],
        'space-before-blocks': 'error',
        'keyword-spacing': 'error',
        'space-infix-ops': 'error',
        'no-multiple-empty-lines': ['error', { 'max': 2 }],
        'brace-style': ['error', '1tbs'],
        'curly': ['error', 'all'],
        'no-var': 'error',
        'prefer-const': 'warn',
        'no-unreachable': 'error'
    }
};
