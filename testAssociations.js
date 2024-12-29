const db = require('./models');

(async () => {
    // Create a user
    const user = await db.User.create({
        username: 'testuser',
        email: 'test@example.com',
        password_hash: 'hashedpassword',
    });

    // Create a client for the user
    const client = await db.Client.create({
        client_id: 'client1',
        client_secret: 'secret123',
        redirect_uri: 'http://localhost:3000/callback',
        owner_id: user.user_id,
    });

    // Create a token for the client and user
    const token = await db.Token.create({
        access_token: 'abc123',
        refresh_token: 'xyz789',
        expires_at: new Date(Date.now() + 3600000), // 1 hour from now
        user_id: user.user_id,
        client_id: client.client_id,
    });

    // Fetch user with related clients
    const fetchedUser = await db.User.findByPk(user.user_id, { include: ['clients'] });
    console.log('User with Clients:', fetchedUser.toJSON());

    // Fetch client with related tokens
    const fetchedClient = await db.Client.findByPk(client.client_id, { include: ['tokens'] });
    console.log('Client with Tokens:', fetchedClient.toJSON());
})();
