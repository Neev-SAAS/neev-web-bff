import { FastifyInstance } from 'fastify';
import { getKcAdminClient, oidcClient } from '../config/keycloak.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import { TokenSet } from 'openid-client';

function isEmailVerified(tokenSet: TokenSet): boolean {
  try {
    const claims = tokenSet.claims();
    if (claims && typeof claims.email_verified === 'boolean') {
      return claims.email_verified;
    }
  } catch (err) {
    // Ignore
  }

  const decodeJwtPayload = (token: string) => {
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = Buffer.from(parts[1], 'base64').toString('utf-8');
        return JSON.parse(payload);
      }
    } catch (err) {
      // Ignore
    }
    return null;
  };

  if (tokenSet.id_token) {
    const decoded = decodeJwtPayload(tokenSet.id_token);
    if (decoded && typeof decoded.email_verified === 'boolean') {
      return decoded.email_verified;
    }
  }

  if (tokenSet.access_token) {
    const decoded = decodeJwtPayload(tokenSet.access_token);
    if (decoded && typeof decoded.email_verified === 'boolean') {
      return decoded.email_verified;
    }
  }

  return false;
}

export async function setupAuthRoutes(app: FastifyInstance) {
  
  // 1. REGISTER
  app.post('/register', {
    schema: {
      description: 'Registers a new user in Keycloak',
      tags: ['Authentication'],
      body: {
        type: 'object',
        required: ['email', 'password', 'firstName', 'lastName'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 6 },
          firstName: { type: 'string' },
          lastName: { type: 'string' }
        }
      },
      response: {
        200: {
          type: 'object',
          properties: {
            message: { type: 'string' }
          }
        },
        400: {
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
      return reply.code(503).send({ error: 'Keycloak OIDC Client is not initialized. Please configure KEYCLOAK_BASE_URL correctly in .env.' });
    }
    const { firstName, lastName, email, password } = req.body as any;
    try {
      const kcAdminClient = await getKcAdminClient();
      
      const user = await kcAdminClient.users.create({
        realm: process.env.KEYCLOAK_REALM!,
        username: email,
        email: email,
        firstName,
        lastName,
        enabled: true,
        emailVerified: false,
        credentials: [{
          type: 'password',
          value: password,
          temporary: false,
        }],
      });

      // Optionally trigger verification email
      await kcAdminClient.users.executeActionsEmail({
        id: user.id,
        clientId: process.env.KEYCLOAK_CLIENT_ID!,
        actions: ['VERIFY_EMAIL'],
      });  

      return reply.send({ message: 'User registered successfully.' });
    } catch (error: any) {
      app.log.error(error);
      
      let sanitizedMessage = 'Registration failed. Please check your details and try again.';
      const errMsg = String(error.message || error);
      
      if (
        errMsg.includes('ECONNREFUSED') ||
        errMsg.includes('ENOTFOUND') ||
        errMsg.includes('ETIMEDOUT') ||
        errMsg.includes('Unexpected token') ||
        errMsg.includes('valid JSON') ||
        errMsg.includes('doctype')
      ) {
        sanitizedMessage = 'Unable to reach the authentication service. Please contact support or try again later.';
      } else if (error.response?.status === 409) {
        sanitizedMessage = 'A user with this email already exists.';
      } else if (error.response?.data) {
        const data = error.response.data;
        if (typeof data === 'object') {
          const rawMsg = data.errorMessage || data.error;
          if (rawMsg) {
            const msgStr = String(rawMsg).toLowerCase();
            if (msgStr.includes('exists') || msgStr.includes('duplicate')) {
              sanitizedMessage = 'A user with this email already exists.';
            } else if (msgStr.includes('password') || msgStr.includes('policy')) {
              sanitizedMessage = 'Password does not meet the security requirements.';
            } else if (!msgStr.includes('http') && !msgStr.includes('/') && msgStr.length < 100) {
              sanitizedMessage = String(rawMsg);
            }
          }
        }
      }

      return reply.code(400).send({ error: sanitizedMessage });
    }
  });

  // 2. LOGIN (Resource Owner Password Credentials Grant)
  app.post('/login', {
    schema: {
      description: 'Logs in user with email and password via Keycloak. Crucially, we pre-check email verification status using the Admin API to avoid creating an active Keycloak session if the email is not verified yet.',
      tags: ['Authentication'],
      body: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string' }
        }
      },
      response: {
        200: {
          type: 'object',
          properties: {
            message: { type: 'string' }
          }
        },
        401: {
          type: 'object',
          properties: {
            error: { type: 'string' }
          }
        },
        403: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            email_verified: { type: 'boolean', default: 'false' },
            redirect: { type: 'string' }
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
      return reply.code(503).send({ error: 'Keycloak OIDC Client is not initialized. Please configure KEYCLOAK_BASE_URL correctly in .env.' });
    }
    const { email, password } = req.body as any;
    try {
      // 1. Pre-check if email is verified via Keycloak Admin Client BEFORE oidcClient.grant
      // to strictly avoid creating a Keycloak session if the email is not verified.
      try {
        const kcAdminClient = await getKcAdminClient();
        const users = await kcAdminClient.users.find({ email, exact: true });
        if (users.length > 0 && !users[0].emailVerified) {
          return reply.code(403).send({
            error: 'Email is not verified',
            email_verified: false,
            redirect: '/verify-email'
          });
        }
      } catch (adminErr) {
        app.log.warn(adminErr, 'Failed to pre-check user emailVerified status via Keycloak Admin Client');
      }

      // 2. Authenticate and perform the grant
      const tokenSet = await oidcClient.grant({
        grant_type: 'password',
        username: email,
        password: password,
        scope: 'openid email profile',
      });

      // Enforce email verification as a safety double check
      let verified = isEmailVerified(tokenSet);
      if (!verified) {
        try {
          const kcAdminClient = await getKcAdminClient();
          const users = await kcAdminClient.users.find({ email, exact: true });
          if (users.length > 0 && users[0].emailVerified) {
            verified = true;
          }
        } catch (adminErr) {
          app.log.warn(adminErr, 'Failed to fetch user emailVerified status via Keycloak Admin Client');
        }
      }

      if (!verified) {
        return reply.code(403).send({
          error: 'Email is not verified',
          email_verified: false,
          redirect: '/verify-email'
        });
      }

      // Secure Cookie configuration
      const cookieOptions = {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict' as const,
      };

      reply.setCookie('access_token', tokenSet.access_token!, cookieOptions);
      if (tokenSet.refresh_token) {
        reply.setCookie('refresh_token', tokenSet.refresh_token, cookieOptions);
      }

      // Return basic user info via token introspection or decoding
      return reply.send({ message: 'Login successful' });
    } catch (error: any) {
      app.log.error(error);
      return reply.code(401).send({ error: 'Invalid credentials' });
    }
  });

  // 3. LOGOUT
  app.post('/logout', {
    schema: {
      description: 'Logs out the user and clears secure cookies',
      tags: ['Authentication'],
      response: {
        200: {
          type: 'object',
          properties: {
            message: { type: 'string' }
          }
        }
      }
    }
  }, async (req, reply) => {
    if (!oidcClient) {
      reply.clearCookie('access_token', { path: '/' });
      reply.clearCookie('refresh_token', { path: '/' });
      return reply.send({ message: 'Logged out successfully (session cleared locally)' });
    }
    try {
      const refreshToken = req.cookies.refresh_token;
      if (refreshToken) {
        // Backchannel logout via Keycloak
        await oidcClient.revoke(refreshToken, 'refresh_token').catch(() => {});
      }
    } catch (e) {
      app.log.error(e as Error, "Failed to revoke token");
    }
    
    reply.clearCookie('access_token', { path: '/' });
    reply.clearCookie('refresh_token', { path: '/' });
    reply.send({ message: 'Logged out successfully' });
  });

  // 5. SOCIAL OAUTH2 Connect
  app.get('/connect/google', {
    schema: {
      description: 'Redirects to Google OAuth2 consent screen',
      tags: ['Authentication'],
      response: {
        302: {
          type: 'object',
          properties: {
            message: { type: 'string' }
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
    const authUrl = oidcClient.authorizationUrl({
      scope: 'openid email profile',
      kc_idp_hint: 'google',
      redirect_uri: `${process.env.APP_URL}/api/auth/callback/google`
    });
    return reply.redirect(authUrl);
  });

  app.get('/connect/linkedin', {
    schema: {
      description: 'Redirects to LinkedIn OAuth2 consent screen',
      tags: ['Authentication'],
      response: {
        302: {
          type: 'object',
          properties: {
            message: { type: 'string' }
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
    const authUrl = oidcClient.authorizationUrl({
      scope: 'openid email profile',
      kc_idp_hint: 'linkedin',
      redirect_uri: `${process.env.APP_URL}/api/auth/callback/linkedin`
    });
    return reply.redirect(authUrl);
  });

  // 6. SOCIAL CALLBACKS
  const handleCallback = async (req: any, reply: any, redirectUri: string) => {
    if (!oidcClient) {
      return reply.redirect(`${process.env.FRONTEND_URL}/login?error=keycloak_not_initialized`);
    }
    try {
      const params = oidcClient.callbackParams(req);
      const tokenSet = await oidcClient.callback(redirectUri, params);

      // Social login providers (Google, LinkedIn, etc.) pre-verify emails, so we bypass manual verification.
      const cookieOptions = {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict' as const,
      };

      reply.setCookie('access_token', tokenSet.access_token!, cookieOptions);
      if (tokenSet.refresh_token) {
        reply.setCookie('refresh_token', tokenSet.refresh_token, cookieOptions);
      }

      // Redirect back to Vue.js frontend
      return reply.redirect(`${process.env.FRONTEND_URL}/dashboard`);
    } catch (error) {
      app.log.error(error as Error, 'Callback error:');
      return reply.redirect(`${process.env.FRONTEND_URL}/login?error=auth_failed`);
    }
  };

  app.get('/callback/google', async (req, reply) => {
    return handleCallback(req, reply, `${process.env.APP_URL}/api/auth/callback/google`);
  });

  app.get('/callback/linkedin', async (req, reply) => {
    return handleCallback(req, reply, `${process.env.APP_URL}/api/auth/callback/linkedin`);
  });

  // 7. RESET PASSWORD
  app.post('/reset-password', {
    schema: {
      description: 'Sends a password reset link to the provided email',
      tags: ['Authentication'],
      body: {
        type: 'object',
        required: ['email'],
        properties: {
          email: { type: 'string', format: 'email' }
        }
      },
      response: {
        200: {
          type: 'object',
          properties: {
            message: { type: 'string' }
          }
        },
        400: {
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
      return reply.code(503).send({ error: 'Keycloak OIDC Client is not initialized. Please configure KEYCLOAK_BASE_URL correctly in .env.' });
    }
    const { email } = req.body as any;
    if (!email) {
      return reply.code(400).send({ error: 'Email is required' });
    }
    
    try {
      const kcAdminClient = await getKcAdminClient();
      
      const users = await kcAdminClient.users.find({ email, exact: true });
      if (users.length === 0) {
        // Return 200 even if user not found to prevent user enumeration
        return reply.send({ message: 'If an account with that email exists, a password reset link has been sent.' });
      }

      const user = users[0];
      if (user.id) {
        await kcAdminClient.users.executeActionsEmail({
          id: user.id,
          clientId: process.env.KEYCLOAK_CLIENT_ID,
          actions: ['UPDATE_PASSWORD'],
        });
      }

      return reply.send({ message: 'If an account with that email exists, a password reset link has been sent.' });
    } catch (error: any) {
      app.log.error(error as Error, 'Reset password failed');
      return reply.code(400).send({ error: 'Failed to initiate password reset' });
    }
  });

  // 8. UPDATE PASSWORD (Authenticated)
  app.post('/update-password', {
    preHandler: requireAuth,
    schema: {
      description: 'Updates the password of the currently logged-in user',
      tags: ['Authentication'],
      security: [{ cookieAuth: [] }],
      body: {
        type: 'object',
        required: ['currentPassword', 'newPassword'],
        properties: {
          currentPassword: { type: 'string', minLength: 1 },
          newPassword: { type: 'string', minLength: 6 }
        }
      },
      response: {
        200: {
          type: 'object',
          properties: {
            message: { type: 'string' }
          }
        },
        400: {
          type: 'object',
          properties: {
            error: { type: 'string' }
          }
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
      return reply.code(503).send({ error: 'Keycloak OIDC Client is not initialized. Please configure KEYCLOAK_BASE_URL correctly in .env.' });
    }

    const { currentPassword, newPassword, current_password, new_password } = req.body as any;
    const currentPwd = currentPassword || current_password;
    const newPwd = newPassword || new_password;

    if (!currentPwd || !newPwd) {
      return reply.code(400).send({ error: 'Both current password and new password are required' });
    }

    const authHeader = req.headers.authorization;
    const accessToken = authHeader?.split(' ')[1];

    if (!accessToken) {
      return reply.code(401).send({ error: 'Unauthorized: No active session' });
    }

    let email: string;
    let userId: string;

    try {
      const payloadBase64 = accessToken.split('.')[1];
      const decodedPayload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
      email = decodedPayload.email;
      userId = decodedPayload.sub;
      if (!email || !userId) {
        throw new Error('Missing email or sub claim in token');
      }
    } catch (err) {
      return reply.code(401).send({ error: 'Unauthorized: Invalid token session' });
    }

    // 1. Verify current password by attempting to login (get OIDC token) with it
    try {
      await oidcClient.grant({
        grant_type: 'password',
        username: email,
        password: currentPwd,
        scope: 'openid',
      });
    } catch (grantErr: any) {
      return reply.code(400).send({ error: 'Incorrect current password' });
    }

    // 2. Change password via Keycloak Admin Client
    try {
      const kcAdminClient = await getKcAdminClient();
      await kcAdminClient.users.resetPassword({
        id: userId,
        credential: {
          type: 'password',
          value: newPwd,
          temporary: false,
        },
      });

      return reply.send({ message: 'Password updated successfully' });
    } catch (error: any) {
      app.log.error(error, 'Failed to update password');
      
      let sanitizedMessage = 'Failed to update password. Please try again.';
      if (error.response?.data) {
        const data = error.response.data;
        if (typeof data === 'object') {
          const rawMsg = data.errorMessage || data.error;
          if (rawMsg) {
            const msgStr = String(rawMsg).toLowerCase();
            if (msgStr.includes('password') || msgStr.includes('policy')) {
              sanitizedMessage = 'Password does not meet the security requirements.';
            } else {
              sanitizedMessage = String(rawMsg);
            }
          }
        }
      } else if (error.message) {
        const msgStr = String(error.message).toLowerCase();
        if (msgStr.includes('policy') || msgStr.includes('password')) {
          sanitizedMessage = 'Password does not meet the security requirements.';
        }
      }

      return reply.code(400).send({ error: sanitizedMessage });
    }
  });

  // 9. VALIDATE SESSION (TOKEN INTROSPECTION)
  const validateSessionSchema = {
    description: 'Validates the current user session/token against Keycloak using the Token Introspection Endpoint',
    tags: ['Authentication'],
    response: {
      200: {
        type: 'object',
        properties: {
          active: { type: 'boolean' },
          scope: { type: 'string' },
          client_id: { type: 'string' },
          username: { type: 'string' },
          token_type: { type: 'string' },
          exp: { type: 'number' },
          iat: { type: 'number' },
          sub: { type: 'string' },
          aud: { type: 'string' },
          iss: { type: 'string' },
          email: { type: 'string' },
          preferred_username: { type: 'string' },
          name: { type: 'string' },
          given_name: { type: 'string' },
          family_name: { type: 'string' },
          email_verified: { type: 'boolean' }
        },
        additionalProperties: true
      },
      401: {
        type: 'object',
        properties: {
          active: { type: 'boolean', default: false },
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
  };

  const validateSessionHandler = async (req: any, reply: any) => {
    if (!oidcClient) {
      return reply.code(503).send({ error: 'Keycloak OIDC Client is not initialized. Please configure KEYCLOAK_BASE_URL correctly in .env.' });
    }

    // Extract access token from Authorization header or cookie
    let accessToken = req.cookies.access_token;
    if (!accessToken && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts[0] === 'Bearer') {
        accessToken = parts[1];
      }
    }

    if (!accessToken) {
      return reply.code(401).send({ active: false, error: 'No active session token found' });
    }

    try {
      // Call Keycloak's Token Introspection Endpoint
      const introspectionResult = await oidcClient.introspect(accessToken);

      if (!introspectionResult.active) {
        return reply.code(401).send({ active: false, error: 'Session is inactive or expired' });
      }

      return reply.send(introspectionResult);
    } catch (error: any) {
      app.log.error(error, 'Token introspection failed');
      return reply.code(401).send({ active: false, error: 'Failed to validate session token against Keycloak' });
    }
  };

  app.post('/validate-session', { schema: validateSessionSchema }, validateSessionHandler);

}