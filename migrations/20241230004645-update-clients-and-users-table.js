module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Handle the Clients table
    const clientsColumns = await queryInterface.describeTable('Clients');

    if (!clientsColumns.clientID) {
      await queryInterface.addColumn('Clients', 'clientID', {
        type: Sequelize.INTEGER,
        allowNull: false,
        unique: true,
      });
    }

    if (!clientsColumns.clientSecret) {
      await queryInterface.addColumn('Clients', 'clientSecret', {
        type: Sequelize.STRING,
        allowNull: false,
      });
    }

    if (!clientsColumns.redirectURI) {
      await queryInterface.addColumn('Clients', 'redirectURI', {
        type: Sequelize.STRING,
        allowNull: false,
      });
    }

    if (!clientsColumns.ownerID) {
      await queryInterface.addColumn('Clients', 'ownerID', {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Users',
          key: 'userID',
        },
      });
    }

    // Handle the Users table
    const usersColumns = await queryInterface.describeTable('Users');

    if (!usersColumns.role) {
      await queryInterface.addColumn('Users', 'role', {
        type: Sequelize.STRING,
        allowNull: false,
      });
    }
  },

  down: async (queryInterface, Sequelize) => {
    // Remove added columns if rolling back
    const clientsColumns = await queryInterface.describeTable('Clients');
    if (clientsColumns.clientID) {
      await queryInterface.removeColumn('Clients', 'clientID');
    }
    if (clientsColumns.clientSecret) {
      await queryInterface.removeColumn('Clients', 'clientSecret');
    }
    if (clientsColumns.redirectURI) {
      await queryInterface.removeColumn('Clients', 'redirectURI');
    }
    if (clientsColumns.ownerID) {
      await queryInterface.removeColumn('Clients', 'ownerID');
    }

    const usersColumns = await queryInterface.describeTable('Users');
    if (usersColumns.role) {
      await queryInterface.removeColumn('Users', 'role');
    }
  },
};
