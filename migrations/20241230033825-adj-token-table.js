module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('Tokens', {
      token_id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true,
      },
      access_token: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true,
      },
      refresh_token: {
        type: Sequelize.STRING,
        allowNull: true,
        unique: true,
      },
      expires_at: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      user_id: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Users', // Assuming you have a 'Users' table
          key: 'user_id',
        },
        onDelete: 'CASCADE',
      },
      client_id: {
        type: Sequelize.STRING,
        allowNull: false,
        references: {
          model: 'Clients', // Assuming you have a 'Clients' table
          key: 'client_id',
        },
        onDelete: 'CASCADE',
      },
      created_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
      updated_at: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW,
      },
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('Tokens');
  },
};
