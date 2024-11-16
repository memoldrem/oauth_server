'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */

  }
    User.init({
    userID: {
      type: DataTypes.INTEGER,
      allowNull: false,
      autoIncrement: true,
      primaryKey: true
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false, // add email formatting criteria thru 'validate'
        validate: { isEmail: true },
        unique: true,
    },
    passwordHash: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    role: {
      type: DataTypes.STRING,
      allowNull: false, // Enforces the NOT NULL constraint
      defaultValue: 'user', // Provides a default value if none is specified
    },
  }, {
    sequelize,
    modelName: 'User',
  });
  return User;
};