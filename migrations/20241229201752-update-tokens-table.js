module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Check if the column "clientID" exists before adding
    const columns = await queryInterface.describeTable('Tokens');

    if (!columns.clientID) {
      await queryInterface.addColumn('Tokens', 'clientID', {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Clients',
          key: 'id',
        },
      });
    }

    if (!columns.userID) {
      await queryInterface.addColumn('Tokens', 'userID', {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: 'Users',
          key: 'userID',
        },
      });
    }
  },

  down: async (queryInterface, Sequelize) => {
    // If you need to remove the columns in case of rollback
    await queryInterface.removeColumn('Tokens', 'clientID');
    await queryInterface.removeColumn('Tokens', 'userID');
  }
};
