import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/**
 * Type-aware linting is deliberate rather than cosmetic here: most of this
 * codebase is socket and stream plumbing, where the bugs that actually bite are
 * unawaited promises and swallowed rejections. Those rules only work when the
 * linter can see types, so every source file must belong to a tsconfig.
 */
const COMPLEXITY_MAX = 12;

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '.cache/**',
      'apps/extension/public/**',
      '**/*.d.ts',
    ],
  },

  // --- TypeScript sources and tests ----------------------------------------
  {
    files: ['**/*.ts', '**/*.tsx'],
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    languageOptions: {
      parserOptions: {
        // Explicit project list rather than `projectService`: the test suites
        // live outside the per-package composite projects and are covered by
        // `tsconfig.tests.json` instead, which project discovery would miss.
        project: [
          './tsconfig.tests.json',
          './packages/*/tsconfig.json',
          './apps/pop/tsconfig.json',
          './apps/connector/tsconfig.json',
          './apps/demo-app/tsconfig.json',
          './apps/extension/tsconfig.json',
        ],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      complexity: ['error', { max: COMPLEXITY_MAX }],

      // An unhandled rejection in a connection handler takes down the process,
      // so a promise that nobody waits on is a defect, not a style choice.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',

      // The store interfaces (SessionStore, OwnershipRegistry) are async so a
      // networked backend can implement them; the in-memory implementations
      // satisfy them synchronously on purpose. That is the documented design,
      // not an oversight, so this rule only produces noise here.
      '@typescript-eslint/require-await': 'off',

      // Deliberate throwaways are spelled with a leading underscore.
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
    },
  },

  // --- Browser extension ----------------------------------------------------
  {
    files: ['apps/extension/**/*.ts', 'apps/extension/**/*.tsx'],
    languageOptions: {
      globals: { ...globals.browser, chrome: 'readonly' },
    },
  },

  // --- Node sources ---------------------------------------------------------
  {
    files: ['packages/**/*.ts', 'apps/pop/**/*.ts', 'apps/connector/**/*.ts', 'apps/demo-app/**/*.ts'],
    languageOptions: {
      globals: globals.node,
    },
  },

  // --- Test suites ----------------------------------------------------------
  {
    files: ['**/test/**/*.ts'],
    rules: {
      // Tests reach into internals and hand fixtures around loosely; the
      // type-safety rules that guard production code only create noise here.
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },

  // --- Config files and plain scripts ---------------------------------------
  // These sit outside every tsconfig, so type-aware rules cannot run on them.
  {
    files: ['*.js', '*.ts', 'scripts/**/*.mjs', 'scripts/**/*.js'],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: {
      globals: globals.node,
      parserOptions: { project: null, projectService: false },
    },
  },
);
