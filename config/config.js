/**
 * Author: Madeline Moldrem
 *
 * This configuration file exports an object containing the database
 * connection settings for three environments: development ("dev"),
 * user acceptance testing ("uat"), and production ("prod"). All configuration
 * values are loaded from environment variables. Ensure that the following
 * environment variables are set: DB_USERNAME, DB_PASSWORD, DB_NAME, DB_HOST, and DIALECT.
 *
 * These settings are used by Sequelize (or a similar ORM) to establish a connection
 * to the appropriate database depending on the current environment.
 */

module.exports = {
  "dev": {
    "username": process.env.DB_USERNAME,
    "password": process.env.DB_PASSWORD,
    "database": process.env.DB_NAME,
    "host": process.env.DB_HOST,
    "dialect": process.env.DIALECT
  },
  "uat": {
    "username": process.env.DB_USERNAME,
    "password": process.env.DB_PASSWORD,
    "database": process.env.DB_NAME,
    "host": process.env.DB_HOST,
    "dialect": process.env.DIALECT
  },
  "prod": {
    "username": process.env.DB_USERNAME,
    "password": process.env.DB_PASSWORD,
    "database": process.env.DB_NAME,
    "host": process.env.DB_HOST,
    "dialect": process.env.DIALECT
  }
};