module.exports = (sequelize, DataTypes) => {
  const Token = sequelize.define('Token', {
      token_id: {
          type: DataTypes.INTEGER,
          primaryKey: true,
          autoIncrement: true,
      },
      access_token: { type: DataTypes.STRING, allowNull: false },
      refresh_token: { type: DataTypes.STRING },
      expires_at: { type: DataTypes.DATE, allowNull: false },
      user_id: { type: DataTypes.INTEGER, allowNull: false },
      client_id: { type: DataTypes.STRING, allowNull: false },
  });

  Token.associate = (models) => {
      Token.belongsTo(models.User, { foreignKey: 'user_id', as: 'user' });
      Token.belongsTo(models.Client, { foreignKey: 'client_id', as: 'client' });
  };

  return Token;
};
