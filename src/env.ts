export interface Env {
  PROXY_SECRET: string; // fake token
  CLOUDFLARE_API_TOKEN: string; // real token
  ZONE_ID: string;
  ZONE_NAME: string;
  ALLOWED_CHALLENGE_NAME: string;
}
