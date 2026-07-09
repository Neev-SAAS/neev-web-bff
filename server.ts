import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import cookie from '@fastify/cookie';
// Swagger imports removed from top level
import { setupAuthRoutes } from './src/controllers/auth.controller.js';
import { setupDashboardRoutes } from './src/controllers/dashboard.controller.js';
import { initKeycloak } from './src/config/keycloak.js';

const startServer = async () => {
  const app = Fastify({
    logger: true,
  });

  // Security Middleware
  await app.register(helmet);

  // CORS for Vue.js Frontend
  await app.register(cors, {
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true, // Allow cookies
  });

  // Cookie Serialization/Deserialization
  await app.register(cookie, {
    secret: process.env.COOKIE_SECRET || 'super-secret-cookie-password-change-me',
    hook: 'onRequest',
    parseOptions: {}
  });

  // OpenAPI Documentation (Development Only)
  if (process.env.NODE_ENV !== 'production') {
    const swagger = (await import('@fastify/swagger')).default;
    const swaggerUi = (await import('@fastify/swagger-ui')).default;
    
    await app.register(swagger, {
      openapi: {
        info: {
          title: 'Neev Web BFF API',
          description: 'API Documentation for the Backend-for-Frontend service',
          version: '0.0.1'
        },
        servers: [
          { url: process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}` }
        ],
        components: {
          securitySchemes: {
            cookieAuth: {
              type: 'apiKey',
              in: 'cookie',
              name: 'access_token'
            }
          }
        }
      }
    });

    await app.register(swaggerUi, {
      routePrefix: '/docs',
      uiConfig: {
        docExpansion: 'list',
        deepLinking: false
      }
    });
  }

  // Healthcheck
  app.get('/health', async () => ({ status: 'ok' }));

  // Register Auth Routes
  await app.register(setupAuthRoutes, { prefix: '/api/auth' });

  // Register Dashboard Routes
  await app.register(setupDashboardRoutes, { prefix: 'api/dashboard' });

  // Initialize Keycloak openid-client config
  try {
    await initKeycloak();
    app.log.info('Keycloak OpenID Client initialized.');
  } catch (err) {
    app.log.error(err, 'Failed to initialize Keycloak OpenID Client');
  }

  const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;

  try {
    // Bind to 0.0.0.0 for containerized environments
    await app.listen({ port: PORT, host: '0.0.0.0' });
    app.log.info(`Server is running at http://localhost:${PORT}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

startServer();
