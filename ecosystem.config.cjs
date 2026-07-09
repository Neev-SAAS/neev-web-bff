module.exports = {
  apps: [
    {
      name: 'neev-web-bff',
      script: './dist/server.cjs',
      instances: 'max',
      exec_mode: 'cluster',
      env: {
        NODE_ENV: 'production',
        PORT: 8000,
        APP_URL: "",
        FRONTEND_URL: "",
        KEYCLOAK_BASE_URL: "",
        KEYCLOAK_REALM: "",
        KEYCLOAK_CLIENT_ID: "",
        KEYCLOAK_CLIENT_SECRET: "",
        COOKIE_SECRET: "",
        GOOGLE_CLIENT_ID: "",
        GOOGLE_CLIENT_SECRET: "",
        LINKEDIN_CLIENT_ID: "",
        LINKEDIN_CLIENT_SECRET: ""
      }
    }
  ]
};
