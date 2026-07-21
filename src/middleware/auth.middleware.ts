import { FastifyRequest, FastifyReply } from 'fastify';
import { oidcClient } from '../config/keycloak.js';
import { TokenSet } from 'openid-client';

export async function requireAuth(req: FastifyRequest, reply: FastifyReply) {
  try {
    // 1. Get tokens from the secure HTTP-Only signed cookie
    let accessToken = req.cookies.access_token;
    let refreshToken = req.cookies.refresh_token;

    if (!accessToken && !refreshToken) {
      return reply.code(401).send({ error: 'Unauthorized: No session found.' });
    }

    // Since fastify-cookie signature can be used, standard practice is verifying it:
    // we use unsigned cookies for tokens in this example but enforce HTTP-Only and strict samesite.
    // If you used signed cookies, unsign them using req.unsignCookie(req.cookies.access_token)

    // Normally, here you decode the JWT to check `exp`.
    // For simplicity, we can do introspection or decode it manually:
    const isExpired = isTokenExpired(accessToken);

    if (isExpired && refreshToken) {
      if (!oidcClient) {
        return reply.code(503).send({ error: 'Keycloak OIDC Client is not initialized.' });
      }
      // 2. Perform silent refresh via openid-client
      const tokenSet = await oidcClient.refresh(refreshToken);
      
      accessToken = tokenSet.access_token;
      refreshToken = tokenSet.refresh_token || refreshToken;

      // 3. Update cookies with new tokens
      reply.setCookie('access_token', accessToken!, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
      });

      if (tokenSet.refresh_token) {
        reply.setCookie('refresh_token', refreshToken!, {
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
        });
      }
    }

    if (!accessToken || isTokenExpired(accessToken)) {
      return reply.code(401).send({ error: 'Unauthorized: Session expired.' });
    }

    // Pass the token along in request for controllers to use
    req.headers.authorization = `Bearer ${accessToken}`;

  } catch (error) {
    req.log.error(error as Error, 'Authentication Error');
    return reply.code(401).send({ error: 'Unauthorized: Invalid session.' });
  }
}

// Simple helper to decode standard JWT and check expiration
function isTokenExpired(token?: string): boolean {
  if (!token) return true;
  try {
    const payloadBase64 = token.split('.')[1];
    const decodedPayload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
    // Give a 30 second drift buffer
    return (decodedPayload.exp * 1000) < (Date.now() + 30000); 
  } catch (e) {
    return true; 
  }
}
