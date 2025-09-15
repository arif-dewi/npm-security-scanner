// Test utility with WebSocket (should be excluded)
const _ws = new WebSocket('ws://localhost:1234');

function createTestWrapper() {
  return { ws: _ws };
}

module.exports = { createTestWrapper };
