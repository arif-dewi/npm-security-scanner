
import React from 'react';
import { render } from '@testing-library/react';
import App from './App';

// Test WebSocket connection (should be excluded)
const ws = new WebSocket('ws://localhost:1234');

test('renders App component', () => {
  render(<App />);
});
        