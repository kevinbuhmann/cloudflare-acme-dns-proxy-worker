import type { Env } from '../env';

export function zoneNameAuthorized(env: Env, name: string | null | undefined): boolean {
  if (!name) {
    return false;
  }

  // ZONE_NAME and the input name could be with or without the trailing dot.

  return matchesRegardlessOfTrailingDot(name, env.ZONE_NAME);
}

export function recordNameAuthorized(env: Env, name: string | null | undefined): boolean {
  if (!name) {
    return false;
  }

  // ALLOWED_CHALLENGE_NAME and the input name could be fully-qualified (with or without the trailing dot)
  // or just the record name without the domain/zone name.

  return (
    matchesRegardlessOfTrailingDot(name, env.ALLOWED_CHALLENGE_NAME) ||
    matchesRegardlessOfTrailingDot(name, `${env.ALLOWED_CHALLENGE_NAME}.${env.ZONE_NAME}`) ||
    matchesRegardlessOfTrailingDot(`${name}.${env.ZONE_NAME}`, env.ALLOWED_CHALLENGE_NAME)
  );
}

function matchesRegardlessOfTrailingDot(value1: string, value2: string): boolean {
  return value1 === value2 || `${value1}.` === value2 || value1 === `${value2}.`;
}
