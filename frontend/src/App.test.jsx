// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import App from './App';

describe('SentinelAI X Frontend Smoke Suite', () => {
  it('renders application container without crashing', () => {
    const { container } = render(<App />);
    expect(container).toBeDefined();
  });
});
