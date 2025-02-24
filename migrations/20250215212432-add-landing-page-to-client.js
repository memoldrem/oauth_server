'use strict';

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn('Clients', 'landing_page', {
      type: Sequelize.STRING,
      allowNull: true,  // Adjust nullability as needed
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.removeColumn('Clients', 'landing_page');
  },
};
