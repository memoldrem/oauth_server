'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Client extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      Client.hasMany(models.Token, {
        foreignKey: 'clientID', // Reference to clientID in Token table
        as: 'tokens', 
      });
    }
  }
  Client.init({
    clientID: {
      type: DataTypes.INTEGER,
      allowNull: false,
      autoIncrement: true, // Automatically increment clientID
      primaryKey: true
    },
    clientSecret: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true,
      }
    },
    redirectURI: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        isUrl: true, // Ensure it's a valid URL
      }
    },
    ownerID: {
      type: DataTypes.INTEGER,
      allowNull: false,
    }
  }, {
    sequelize,
    modelName: 'Client',
  });
  return Client;
};