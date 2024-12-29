module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
      user_id: {
          type: DataTypes.INTEGER,
          primaryKey: true,
          autoIncrement: true,
      },
      username: { type: DataTypes.STRING, unique: true, allowNull: false },
      email: { type: DataTypes.STRING, unique: true, allowNull: false },
      password_hash: { type: DataTypes.STRING, allowNull: false },
      role: { type: DataTypes.STRING, defaultValue: 'user', allowNull: false },
  });

  User.associate = (models) => {
      User.hasMany(models.Client, { foreignKey: 'owner_id', as: 'clients' });
      User.hasMany(models.Token, { foreignKey: 'user_id', as: 'tokens' });
  };

  return User;
};
