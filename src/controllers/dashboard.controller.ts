import { FastifyInstance } from 'fastify';
import { oidcClient } from '../config/keycloak.js';
import { requireAuth } from '../middleware/auth.middleware.js';

export async function setupDashboardRoutes(app: FastifyInstance) {
  // ME (Profile info)
  app.get('/profile', {
    preHandler: requireAuth,
    schema: {
      description: 'Gets the currently logged-in user profile info',
      tags: ['Dashboard'],
      security: [{ cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          additionalProperties: true
        },
        401: {
          type: 'object',
          properties: {
            error: { type: 'string' }
          }
        },
        503: {
          type: 'object',
          properties: {
            error: { type: 'string' }
          }
        }
      }
    }
  }, async (req, reply) => {
    if (!oidcClient) {
      return reply.code(503).send({ error: 'Keycloak OIDC Client is not initialized.' });
    }
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader?.split(' ')[1];
      
      if (!token) throw new Error("No token");

      const userinfo = await oidcClient.userinfo(token);
      return reply.send(userinfo);
    } catch (error) {
      console.log(error)
       return reply.code(401).send({ error: 'Failed to fetch user info' });
    }
  });
}