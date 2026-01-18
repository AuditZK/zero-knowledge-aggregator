// Test setup - import reflect-metadata for tsyringe decorators
import 'reflect-metadata';

// Suppress console output during tests unless DEBUG is set
if (!process.env.DEBUG) {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'info').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
}

// Reset all mocks between tests
beforeEach(() => {
  jest.clearAllMocks();
});
