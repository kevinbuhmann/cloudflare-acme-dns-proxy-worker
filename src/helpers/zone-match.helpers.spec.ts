import { describe, expect, it } from 'vitest';

import type { Env } from '../env';
import { recordNameAuthorized, zoneNameAuthorized } from './zone-match.helpers';

describe('zone match helpers', () => {
  describe('zoneNameAuthorized', () => {
    it('returns false for null input', () => {
      expect(zoneNameAuthorized(makeEnv(), null)).toBe(false);
    });

    it('returns false for undefined input', () => {
      expect(zoneNameAuthorized(makeEnv(), undefined)).toBe(false);
    });

    it('returns false for empty string input', () => {
      expect(zoneNameAuthorized(makeEnv(), '')).toBe(false);
    });

    const passing = [...withExampleDotComZonePermutations(...withAndWithoutTrailingDot('example.com'))];

    passing.forEach(({ input, ZONE_NAME }) => {
      it(`returns true for '${input}' with ZONE_NAME '${ZONE_NAME}'`, () => {
        expect(zoneNameAuthorized(makeEnv({ ZONE_NAME }), input)).toBe(true);
      });
    });

    const failing = [
      ...withExampleDotComZonePermutations(...withAndWithoutTrailingDot('home.com')),
      ...withExampleDotComZonePermutations(...withAndWithoutTrailingDot('home.example.com')),
    ];

    failing.forEach(({ input, ZONE_NAME }) => {
      it(`returns false for '${input}' with ZONE_NAME '${ZONE_NAME}'`, () => {
        expect(zoneNameAuthorized(makeEnv({ ZONE_NAME }), input)).toBe(false);
      });
    });
  });

  describe('recordNameAuthorized', () => {
    it('returns false for null input', () => {
      expect(recordNameAuthorized(makeEnv(), null)).toBe(false);
    });

    it('returns false for undefined input', () => {
      expect(recordNameAuthorized(makeEnv(), undefined)).toBe(false);
    });

    it('returns false for empty string input', () => {
      expect(recordNameAuthorized(makeEnv(), '')).toBe(false);
    });

    const passing = [
      ...withHomeDotExampleDotComChallengePermutations('_acme-challenge.home'),
      ...withHomeDotExampleDotComChallengePermutations(...withAndWithoutTrailingDot('_acme-challenge.home.example.com')),
    ];

    passing.forEach(({ input, ZONE_NAME, ALLOWED_CHALLENGE_NAME }) => {
      it(`returns true for '${input}' with ALLOWED_CHALLENGE_NAME '${ALLOWED_CHALLENGE_NAME}' and ZONE_NAME '${ZONE_NAME}'`, () => {
        expect(recordNameAuthorized(makeEnv({ ZONE_NAME, ALLOWED_CHALLENGE_NAME }), input)).toBe(true);
      });
    });

    const failing = [
      ...withHomeDotExampleDotComChallengePermutations('_acme-challenge'),
      ...withHomeDotExampleDotComChallengePermutations(...withAndWithoutTrailingDot('_acme-challenge.home.com')),
      ...withHomeDotExampleDotComChallengePermutations(...withAndWithoutTrailingDot('_acme-challenge.example.com')),
      ...withHomeDotExampleDotComChallengePermutations(...withAndWithoutTrailingDot('_acme-challenge.example.home.com')),
    ];

    failing.forEach(({ input, ZONE_NAME, ALLOWED_CHALLENGE_NAME }) => {
      it(`returns false for '${input}' with ALLOWED_CHALLENGE_NAME '${ALLOWED_CHALLENGE_NAME}' and ZONE_NAME '${ZONE_NAME}'`, () => {
        expect(recordNameAuthorized(makeEnv({ ZONE_NAME, ALLOWED_CHALLENGE_NAME }), input)).toBe(false);
      });
    });
  });
});

function makeEnv({ ZONE_NAME = 'example.com', ALLOWED_CHALLENGE_NAME = '_acme-challenge.home' } = {}): Env {
  return {
    PROXY_SECRET: 'fake',
    CLOUDFLARE_API_TOKEN: 'real',
    ZONE_ID: 'zone-id',
    ZONE_NAME,
    ALLOWED_CHALLENGE_NAME,
  };
}

function withAndWithoutTrailingDot(input: string) {
  return [input, `${input}.`];
}

function withExampleDotComZonePermutations(...inputs: string[]) {
  return inputs.flatMap(input => [
    { input, ZONE_NAME: 'example.com' },
    { input, ZONE_NAME: 'example.com.' },
  ]);
}

function withHomeDotExampleDotComChallengePermutations(...inputs: string[]) {
  return inputs.flatMap(input => [
    // zone name has trailing dot
    { input, ALLOWED_CHALLENGE_NAME: '_acme-challenge.home', ZONE_NAME: 'example.com.' },
    { input, ALLOWED_CHALLENGE_NAME: '_acme-challenge.home.example.com', ZONE_NAME: 'example.com.' },
    { input, ALLOWED_CHALLENGE_NAME: '_acme-challenge.home.example.com.', ZONE_NAME: 'example.com.' },

    // zone name does not have trailing dot
    { input, ALLOWED_CHALLENGE_NAME: '_acme-challenge.home', ZONE_NAME: 'example.com' },
    { input, ALLOWED_CHALLENGE_NAME: '_acme-challenge.home.example.com', ZONE_NAME: 'example.com' },
    { input, ALLOWED_CHALLENGE_NAME: '_acme-challenge.home.example.com.', ZONE_NAME: 'example.com' },
  ]);
}
