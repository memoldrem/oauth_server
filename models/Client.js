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
    clientID: DataTypes.INTEGER,
    clientSecret: DataTypes.STRING,
    redirectURI: DataTypes.STRING,
    ownerID: DataTypes.INTEGER
  }, {
    sequelize,
    modelName: 'Client',
  });
  return Client;
};