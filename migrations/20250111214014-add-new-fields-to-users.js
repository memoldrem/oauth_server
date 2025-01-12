'use strict';

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn('Users', 'first_name', {
      type: Sequelize.STRING,
      allowNull: true,
    });
    await queryInterface.addColumn('Users', 'last_name', {
      type: Sequelize.STRING,
      allowNull: true,
    });
    await queryInterface.addColumn('Users', 'date_of_birth', {
      type: Sequelize.DATEONLY,
      allowNull: true,
    });
    await queryInterface.changeColumn('Users', 'updatedAt', {
      type: Sequelize.DATE,
      allowNull: false,
      defaultValue: Sequelize.fn('NOW'),
    });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.removeColumn('Users', 'first_name');
    await queryInterface.removeColumn('Users', 'last_name');
    await queryInterface.removeColumn('Users', 'date_of_birth');
    await queryInterface.changeColumn('Users', 'updatedAt', {
      type: Sequelize.DATE,
      allowNull: false,
    });
  },
};
