const model = {
    getClient: async (clientId, clientSecret) => {
        if (clientId === 'client_id' && clientSecret === 'client_secret') {
            return { id: clientId, grants: ['password', 'refresh_token'] };
        }
        return null;
    },

    getUser: async (username, password) => {
        if (username === 'user' && password === 'pass') {
            return { id: '123' };
        }
        return null;
    },

    saveToken: async (token, client, user) => {
        return {
            accessToken: token.accessToken,
            accessTokenExpiresAt: token.accessTokenExpiresAt,
            refreshToken: token.refreshToken,
            refreshTokenExpiresAt: token.refreshTokenExpiresAt,
            client,
            user,
        };
    },

    getAccessToken: async (accessToken) => {
        // Validate token
        if (accessToken === 'valid_token') {
            return {
                accessToken,
                accessTokenExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
                client: { id: 'client_id' },
                user: { id: '123' },
            };
        }
        return null;
    },

    getRefreshToken: async (refreshToken) => {
        if (refreshToken === 'valid_refresh_token') {
            return {
                refreshToken,
                refreshTokenExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
                client: { id: 'client_id' },
                user: { id: '123' },
            };
        }
        return null;
    },

    revokeToken: async (token) => {
        // Logic to revoke token
        return true;
    },
};

module.exports = model;
