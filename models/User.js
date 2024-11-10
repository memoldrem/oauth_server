const { DataTypes } = require('sequelize');
// const sequelize = new Sequelize('postgres://user:pass@example.com:5432/dbname') // need to change this!

const User = sequelize.define(
  'User',
  {
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
module.exports = User;
