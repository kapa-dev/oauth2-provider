import jwt from "jsonwebtoken";

const memory = {
  clients: {
    [process.env.OAUTH_CLIENT_ID]: {
      clientId: process.env.OAUTH_CLIENT_ID,
      clientSecret: process.env.OAUTH_CLIENT_SECRET,
      grants: ["authorization_code", "refresh_token", "password", "client_credentials"],
      redirectUris: [process.env.OAUTH_REDIRECT_URI]
    }
  },

  users: {
    [process.env.OAUTH_USER_ID]: {
      id: process.env.OAUTH_USER_ID,
      username: process.env.OAUTH_USER_USERNAME,
      password: process.env.OAUTH_USER_PASSWORD,
      email: process.env.OAUTH_USER_EMAIL,
      firstName: process.env.OAUTH_USER_FIRSTNAME,
      lastName: process.env.OAUTH_USER_LASTNAME,
    }
  },

  authorizationCodes: {},   // code → { client, user, expiresAt }
  accessTokens: {},          // token → { ... }
  refreshTokens: {}          // token → { ... }
};

export default {
  // ---------------------------------------------------------------------------
  // CLIENT
  // ---------------------------------------------------------------------------
  getClient: async function (clientId, clientSecret) {
    const client = memory.clients[clientId];
    if (!client) return null;
    if (clientSecret && client.clientSecret !== clientSecret) return null;
    return client;
  },

  // ---------------------------------------------------------------------------
  // AUTHORIZATION CODE
  // ---------------------------------------------------------------------------
  saveAuthorizationCode: async function (code, client, user) {
    memory.authorizationCodes[code.authorizationCode] = {
      ...code,
      client,
      user
    };
    return { ...code, client, user };
  },

  getAuthorizationCode: async function (authCode) {
    return memory.authorizationCodes[authCode] || null;
  },

  revokeAuthorizationCode: async function (code) {
    delete memory.authorizationCodes[code.authorizationCode];
    return true;
  },

  // ---------------------------------------------------------------------------
  // TOKEN
  // ---------------------------------------------------------------------------
  saveToken: async function (token, client, user) {
    const payload = {
      userId: user.id,
      clientId: client.clientId,
      scope: token.scope
    };

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h"
    });

    const tokenData = {
      accessToken,
      accessTokenExpiresAt: new Date(Date.now() + 3600 * 1000),
      refreshToken: token.refreshToken,
      refreshTokenExpiresAt: token.refreshTokenExpiresAt,
      client,
      user
    };

    memory.accessTokens[accessToken] = tokenData;

    if (token.refreshToken) {
      memory.refreshTokens[token.refreshToken] = {
        refreshToken: token.refreshToken,
        refreshTokenExpiresAt: token.refreshTokenExpiresAt,
        client,
        user
      };
    }

    return tokenData;
  },

  getAccessToken: async function (accessToken) {
    return memory.accessTokens[accessToken] || null;
  },

  getRefreshToken: async function (refreshToken) {
    return memory.refreshTokens[refreshToken] || null;
  },

  revokeToken: async function (token) {
    delete memory.refreshTokens[token.refreshToken];
    return true;
  },

  // ---------------------------------------------------------------------------
  // PASSWORD GRANT (optional)
  // ---------------------------------------------------------------------------
  getUser: async function (username, password) {
    const user = Object.values(memory.users).find(u => u.username === username);
    if (!user || user.password !== password) return null;
    return user;
  }
};
