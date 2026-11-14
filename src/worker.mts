import { NotFoundError } from 'cloudflare/core/error.mjs';
import { Records } from 'cloudflare/resources/dns/records';
import { createClient } from 'cloudflare/tree-shakable';

interface Env {
  PROXY_SECRET: string; // fake token
  CLOUDFLARE_API_TOKEN: string; // real token
  ZONE_ID: string;
  ZONE_NAME: string;
  ALLOWED_CHALLENGE_NAME: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    console.log('Incoming request', { method: request.method, url: request.url });

    if (!(await requestAuthorized(env, request))) {
      console.error('Unauthorized access attempt');
      return jsonError('Unauthorized', 401);
    }

    const requestUrl = new URL(request.url);
    const requestMethod = request.method;

    // Zone discovery: only permit lookup of the configured zone.
    if (requestUrl.pathname === '/client/v4/zones' && requestMethod === 'GET') {
      const readQueryParamsResult = readQueryParams(requestUrl.searchParams, ['name']);
      if ('error' in readQueryParamsResult) {
        console.error('Zone lookup rejected - invalid query parameters', {
          requestParams: Object.fromEntries(requestUrl.searchParams),
          error: readQueryParamsResult.error,
        });
        return jsonError(readQueryParamsResult.error, 403);
      }

      const requestParams = readQueryParamsResult.params;

      if (!zoneNameAuthorized(env, requestParams.name)) {
        console.error('Zone lookup rejected - zone not allowed', { requestParams });
        return jsonError('Zone not allowed', 403);
      }

      const allowedParams = new URLSearchParams({
        name: requestParams.name,
      });

      console.log('Zone lookup authorized', { requestParams });
      return cloudflare(env, `/zones?${allowedParams}`);
    }

    const recordsPath = `/client/v4/zones/${env.ZONE_ID}/dns_records`;

    // List records. The Caddy Cloudflare provider needs this when locating records to delete or update.
    if (requestUrl.pathname === recordsPath && requestMethod === 'GET') {
      const readQueryParamsResult = readQueryParams(requestUrl.searchParams, ['type', 'name']);
      if ('error' in readQueryParamsResult) {
        console.error('Record query rejected - invalid query parameters', {
          requestParams: Object.fromEntries(requestUrl.searchParams),
          error: readQueryParamsResult.error,
        });
        return jsonError(readQueryParamsResult.error, 403);
      }

      const requestParams = readQueryParamsResult.params;

      if (requestParams.type !== 'TXT' || !recordNameAuthorized(env, requestParams.name)) {
        console.error('Record query rejected - type or name not allowed', { requestParams });
        return jsonError('Record query not allowed', 403);
      }

      const allowedParams = new URLSearchParams({
        type: requestParams.type,
        name: requestParams.name,
      });

      console.log('List records authorized', { requestParams });
      return cloudflare(env, `/zones/${env.ZONE_ID}/dns_records?${allowedParams}`);
    }

    // Create a TXT challenge record if allowed.
    if (requestUrl.pathname === recordsPath && requestMethod === 'POST') {
      const rawRequestText = await request.text();

      if (rawRequestText.length > 4096) {
        return jsonError('Request too large', 413);
      }

      let requestedRecord: unknown;
      try {
        requestedRecord = JSON.parse(rawRequestText);
      } catch {
        return jsonError('Invalid JSON', 400);
      }

      if (requestedRecord === null || typeof requestedRecord !== 'object' || Array.isArray(requestedRecord)) {
        console.error('Record creation rejected - invalid input type', { requestedRecord });
        return jsonError('Expected a DNS record object', 400);
      }

      if (
        !('type' in requestedRecord) ||
        requestedRecord.type !== 'TXT' ||
        !('name' in requestedRecord) ||
        typeof requestedRecord.name !== 'string' ||
        !recordNameAuthorized(env, requestedRecord.name) ||
        !('content' in requestedRecord) ||
        typeof requestedRecord.content !== 'string' ||
        requestedRecord.content.length > 2048
      ) {
        console.error('Record creation rejected - validation failed', { requestedRecord });
        return jsonError('Record not allowed', 403);
      }

      const allowedRecord = {
        type: requestedRecord.type,
        name: requestedRecord.name,
        content: requestedRecord.content,
      };

      console.log('Creating DNS-01 challenge record', { allowedRecord });
      return cloudflare(env, `/zones/${env.ZONE_ID}/dns_records`, 'POST', JSON.stringify(allowedRecord));
    }

    // Delete a record only after confirming its identity.
    const recordIdPathRegex = new RegExp(`^${recordsPath}/([a-f0-9]{32})$`);
    const recordIdPathMatch = requestUrl.pathname.match(recordIdPathRegex);

    if (recordIdPathMatch && requestMethod === 'DELETE') {
      const recordId = recordIdPathMatch[1];

      console.log('Deleting DNS-01 challenge record', { recordId });

      const cloudFlareClient = createClient({
        apiToken: env.CLOUDFLARE_API_TOKEN,
        resources: [Records],
      });

      let existingRecord: Records.RecordResponse;

      try {
        existingRecord = await cloudFlareClient.dns.records.get(recordId, { zone_id: env.ZONE_ID });

        if (existingRecord.type !== 'TXT' || !recordNameAuthorized(env, existingRecord.name)) {
          console.error('Delete record rejected - does not belong to challenge', { existingRecord });
          return jsonError('Record does not belong to challenge', 403);
        }
      } catch (error) {
        if (error instanceof NotFoundError) {
          console.error('Delete record rejected - record not found', { recordId });
          return jsonError('Record does not belong to challenge', 403);
        } else {
          console.error('Failed to fetch existing record', { error: (error as Error).message });
          return jsonError('Failed to fetch existing record', 500);
        }
      }

      console.log('Delete DNS-01 challenge record authorized', { existingRecord });
      return cloudflare(env, `/zones/${env.ZONE_ID}/dns_records/${recordId}`, 'DELETE');
    }

    console.error('Operation not allowed - unsupported endpoint/method');
    return jsonError('Operation not allowed', 403);
  },
};

async function requestAuthorized(env: Env, request: Request): Promise<boolean> {
  const supplied = request.headers.get('Authorization') ?? '';
  const expected = `Bearer ${env.PROXY_SECRET}`;

  const encoder = new TextEncoder();

  const [suppliedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(supplied)),
    crypto.subtle.digest('SHA-256', encoder.encode(expected)),
  ]);

  return crypto.subtle.timingSafeEqual(suppliedHash, expectedHash);
}

function zoneNameAuthorized(env: Env, name: string | null | undefined): boolean {
  if (!name) {
    return false;
  }

  // ZONE_NAME and the input name could be with or without the trailing dot.

  return matchesRegardlessOfTrailingDot(name, env.ZONE_NAME);
}

function recordNameAuthorized(env: Env, name: string | null | undefined): boolean {
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

function readQueryParams<const TKeys extends readonly string[]>(
  params: URLSearchParams,
  keys: TKeys,
): { params: Record<TKeys[number], string> } | { error: string } {
  const result: Record<string, string> = {};

  for (const key of params.keys()) {
    if (!keys.includes(key)) {
      return { error: `Parameter "${key}" is not allowed` };
    }
    const [value, ...rest] = params.getAll(key);
    if (rest.length > 0) {
      return { error: `Multiple values for parameter "${key}" are not allowed` };
    }
    result[key] = value;
  }

  if (keys.some(key => !(key in result))) {
    return { error: `Missing required query parameter` };
  }

  return { params: result as Record<TKeys[number], string> };
}

function jsonError(message: string, status: number): Response {
  return Response.json({ success: false, errors: [{ message }] }, { status });
}

async function cloudflare(env: Env, path: string, method = 'GET', body?: string): Promise<Response> {
  const headers = new Headers({
    Authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
    'Content-Type': 'application/json',
  });

  return fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method,
    headers,
    body,
  });
}
