/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts', '**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
    '!src/__tests__/**',
    '!src/proto/**',
    '!src/types/**',
  ],
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/__tests__/',
    '/proto/',
  ],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        // Override some tsconfig options for tests
        strict: true,
        experimentalDecorators: true,
        emitDecoratorMetadata: true,
        esModuleInterop: true,
        // Allow tests to compile without unused var errors
        noUnusedLocals: false,
        noUnusedParameters: false,
      }
    }]
  },
  setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup.ts'],
  // Mock tsyringe by default
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1'
  },
  // Increase timeout for integration tests
  testTimeout: 10000,
};
