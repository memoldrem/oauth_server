const bcrypt = require('bcrypt');

const users = [
    { id: 1, username: 'test', password: bcrypt.hashSync('password', 10) },
];

const clients = [
    { clientId: 'client1', clientSecret: 'secret1', grants: ['password', 'client_credentials'] },
];

let tokens = []; // Temporary in-memory token store

module.exports = {
    // Authenticate a user with the password grant type
    getUser: async (username, password) => {
        const user = users.find((u) => u.username === username);
        if (user && (await bcrypt.compare(password, user.password))) {
            return user;
        }
        return null;
    },

    // Validate the client
    getClient: (clientId, clientSecret) => {
        const client = clients.find(
            (c) => c.clientId === clientId && c.clientSecret === clientSecret
        );
        return client ? { ...client, grants: client.grants } : null;
    },

    // Save the token
    saveToken: (token, client, user) => {
        const newToken = { ...token, client, user };
        tokens.push(newToken);
        return newToken;
    },

    // Get the token
    getAccessToken: (accessToken) => {
        const token = tokens.find((t) => t.accessToken === accessToken);
        return token || null;
    },

    // Revoke a token (optional)
    revokeToken: (token) => {
        tokens = tokens.filter((t) => t.accessToken !== token.accessToken);
        return true;
    },

    // Validate scopes (optional)
    validateScope: (user, client, scope) => scope === null || scope === '',

    // Generate custom tokens if needed
    generateAccessToken: (client, user, scope) => {
        return `token-${Math.random().toString(36).substring(7)}`;
    },
};
