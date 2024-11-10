const { DataTypes } = require('sequelize');
// const sequelize = new Sequelize('postgres://user:pass@example.com:5432/dbname') 

const Token = sequelize.define(
  'Token',
  {
    tokenID: {
        type: DataTypes.INTEGER,
        allowNull: false,
        autoIncrement: true,
        primaryKey: true
    },
    access_token: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true, // Ensure the access_token is unique
    },
    refresh_token: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true, // Ensure the refresh_token is unique
    },
    expires_at: {
        type: DataTypes.DATE,
        allowNull: false,
        },
    }, {

    });

Token.belongsTo(Client, {
    foreignKey: 'clientID', // Reference to client_id from Client model
    as: 'client', // Alias to reference the associated client
});