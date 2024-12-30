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
      owner_id: { type: DataTypes.INTEGER, allowNull: false },
  }, {
    timestamps: true, // Enable Sequelize timestamps
    createdAt: 'created_at', // Map Sequelize `createdAt` to `created_at`
    updatedAt: 'updated_at', // Map Sequelize `updatedAt` to `updated_at`
});

  Client.associate = (models) => {
      Client.belongsTo(models.User, { foreignKey: 'owner_id', as: 'owner' });
      Client.hasMany(models.Token, { foreignKey: 'client_id', as: 'tokens' });
  };

  return Client;
};
