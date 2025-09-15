
// Test utility with WebSocket (should be excluded)
const ws = new WebSocket('ws://localhost:1234');

export function createTestWrapper() {
  return { ws };
}
        