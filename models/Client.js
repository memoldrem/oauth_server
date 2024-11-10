const { DataTypes } = require('sequelize');
// const sequelize = new Sequelize('postgres://user:pass@example.com:5432/dbname') dont think we need, check index.js

const Client = sequelize.define(
  'Client',
  {
    clientID: {
      type: DataTypes.INTEGER,
      allowNull: false,
      autoIncrement: true,
      primaryKey: true
    },
    clientSecret: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    passwordHash: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    role: {
        type: DataTypes.STRING,
        allowNull: false,
    },
  },
  {
    // Other model options go here
  },
);
 // allowNull defaults to true
// `sequelize.define` also returns the model
module.exports = Client;