import { describe, expect, it } from 'vitest';
import { PolicyParser } from '../src/core/policy-parser.js';

describe('PolicyParser', () => {
  it('parses markdown policy and extracts requirements', () => {
    const parser = new PolicyParser();
    const policy = parser.parseMarkdown(
      `# Access Control Policy

**Status:** Active
**Owner:** Security Team

## Requirements

1. MFA is required for admin access
- Category: Access
- Severity: High
`,
      'access-policy.md',
    );

    expect(policy.name).toBe('Access Control Policy');
    expect(policy.status).toBe('active');
    expect(policy.requirements.length).toBeGreaterThan(0);
    expect(policy.requirements[0].severity).toBe('high');
  });

  it('returns active policies only', () => {
    const parser = new PolicyParser();
    parser.parseMarkdown('# Draft Policy\n\n**Status:** Draft\n\n## Requirements\n\n1. Baseline', 'draft.md');
    parser.parseMarkdown('# Active Policy\n\n**Status:** Active\n\n## Requirements\n\n1. Baseline', 'active.md');

    const active = parser.getActivePolicies();
    expect(active.length).toBe(1);
    expect(active[0].name).toBe('Active Policy');
  });
});
