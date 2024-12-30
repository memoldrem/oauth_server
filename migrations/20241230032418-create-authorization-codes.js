'use strict';

module.exports = {
    up: async (queryInterface, Sequelize) => {
        await queryInterface.createTable('AuthorizationCodes', {
            authorization_code: {
                type: Sequelize.STRING,
                allowNull: false,
                primaryKey: true,
            },
            user_id: {
                type: Sequelize.INTEGER,
                allowNull: false,
                references: {
                    model: 'Users', // Name of the Users table
                    key: 'user_id',
                },
                onUpdate: 'CASCADE',
                onDelete: 'CASCADE',
            },
            client_id: {
                type: Sequelize.INTEGER,
                allowNull: false,
                references: {
                    model: 'Clients', // Name of the Clients table
                    key: 'client_id',
                },
                onUpdate: 'CASCADE',
                onDelete: 'CASCADE',
            },
            redirect_uri: {
                type: Sequelize.STRING,
                allowNull: false,
            },
            expires_at: {
                type: Sequelize.DATE,
                allowNull: false,
            },
            state: {
                type: Sequelize.STRING,
                allowNull: false,
            },
            createdAt: {
                allowNull: false,
                type: Sequelize.DATE,
                defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
            },
            updatedAt: {
                allowNull: false,
                type: Sequelize.DATE,
                defaultValue: Sequelize.literal('CURRENT_TIMESTAMP'),
            },
        });
    },

    down: async (queryInterface, Sequelize) => {
        await queryInterface.dropTable('AuthorizationCodes');
    },
};
