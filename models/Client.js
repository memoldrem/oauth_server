module.exports = (sequelize, DataTypes) => {
  const Client = sequelize.define('Client', {
    client_id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
      client_secret: { type: DataTypes.STRING, allowNull: false },
      client_name: { type: DataTypes.STRING, allowNull: false },
      redirect_uri: { type: DataTypes.STRING, allowNull: false },
      landing_page: { type: DataTypes.STRING, allowNull: true },
      owner_id: { type: DataTypes.INTEGER, allowNull: false },
  }, {
      tableName: 'clients',
      timestamps: true,
  });

  Client.associate = (models) => {
      Client.belongsTo(models.User, { foreignKey: 'owner_id', as: 'owner' });
      Client.hasMany(models.Token, { foreignKey: 'client_id', as: 'tokens' });
  };

  return Client;
};
