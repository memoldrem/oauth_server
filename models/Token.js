'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Token extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
        Token.belongsTo(User, {
            foreignKey: 'userID', 
            as: 'user',           
          });
        Token.belongsTo(User, {
            foreignKey: 'clientID', 
            as: 'client',           
          });
    }
  }
  Token.init({
    tokenID: DataTypes.INTEGER,
    access_token: DataTypes.STRING,
    refresh_token: DataTypes.STRING,
    expires_at: DataTypes.DATE,
    clientID: DataTypes.INTEGER,
    userID: DataTypes.INTEGER,
  }, {
    sequelize,
    modelName: 'Token',
  });
  return Token;
};