const App = require('./App');

// Test WebSocket connection (should be excluded)
const _ws = new WebSocket('ws://localhost:1234');

test('renders App component', () => {
  const result = App();
  expect(result).toBe('Hello World');
});
