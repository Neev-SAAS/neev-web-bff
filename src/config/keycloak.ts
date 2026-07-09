import { Issuer, Client, custom } from 'openid-client';
import KcAdminClient from '@keycloak/keycloak-admin-client';

export let oidcClient: Client;

export async function initKeycloak() {
  if (!process.env.KEYCLOAK_BASE_URL || process.env.KEYCLOAK_BASE_URL.includes('your-keycloak-domain.com')) {
    console.warn("Skipping Keycloak initialization: Placeholder or missing KEYCLOAK_BASE_URL environment variable.");
    return;
  }
  
  const baseUrl = process.env.KEYCLOAK_BASE_URL.replace(/\/+$/, '');
  const issuerUrl = `${baseUrl}/realms/${process.env.KEYCLOAK_REALM}`;
  try {
    const issuer = await Issuer.discover(issuerUrl);
    oidcClient = new issuer.Client({
      client_id: process.env.KEYCLOAK_CLIENT_ID!,
      client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
      redirect_uris: [`${process.env.APP_URL}/api/auth/callback/google`, `${process.env.APP_URL}/api/auth/callback/linkedin`],
      response_types: ['code'],
    });
  } catch (error: any) {
    const errStr = String(error.message || error);
    if (errStr.includes('Unexpected token') || errStr.includes('valid JSON') || errStr.includes('doctype')) {
      console.warn(`[Keycloak Config Warning] Could not discover Keycloak at "${issuerUrl}".`);
      console.warn(`The server returned an HTML page instead of valid OpenID Connect JSON metadata.`);
      console.warn(`If Keycloak is running on your local machine (e.g. http://localhost:8080), please note that this containerized applet running in the cloud cannot directly connect to your machine's 'localhost'.`);
      console.warn(`To make this work in the preview environment, you can use a tunneling tool (like ngrok or localtunnel) to expose your local Keycloak instance, then set the public URL in KEYCLOAK_BASE_URL inside your .env file.`);
    } else {
      console.warn(`Keycloak generic initialization failed: ${error.message || error}`);
    }
  }
}

export async function getKcAdminClient() {
  const baseUrl = process.env.KEYCLOAK_BASE_URL!.replace(/\/+$/, '');
  const kcAdminClient = new KcAdminClient({
    baseUrl: baseUrl,
    realmName: process.env.KEYCLOAK_REALM,
  });

  await kcAdminClient.auth({
    grantType: 'client_credentials',
    clientId: process.env.KEYCLOAK_CLIENT_ID!,
    clientSecret: process.env.KEYCLOAK_CLIENT_SECRET,
  });
  
  return kcAdminClient;
}
