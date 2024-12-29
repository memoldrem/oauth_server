module.exports = (sequelize, DataTypes) => {
  const Client = sequelize.define('Client', {
      client_id: {
          type: DataTypes.STRING,
          primaryKey: true,
      },
      client_secret: { type: DataTypes.STRING, allowNull: false },
      redirect_uri: { type: DataTypes.STRING, allowNull: false },
      owner_id: { type: DataTypes.INTEGER, allowNull: false },
  });

  Client.associate = (models) => {
      Client.belongsTo(models.User, { foreignKey: 'owner_id', as: 'owner' });
      Client.hasMany(models.Token, { foreignKey: 'client_id', as: 'tokens' });
  };

  return Client;
};
