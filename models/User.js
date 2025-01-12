const User = sequelize.define(
  'User',
  {
    user_id: {
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    username: {
      type: Sequelize.STRING,
      allowNull: false,
    },
    email: {
      type: Sequelize.STRING,
      allowNull: false,
      unique: true,
    },
    first_name: {
      type: Sequelize.STRING,
      allowNull: true,
    },
    last_name: {
      type: Sequelize.STRING,
      allowNull: true,
    },
    date_of_birth: {
      type: Sequelize.DATEONLY,
      allowNull: true,
    },
    password_hash: {
      type: Sequelize.STRING,
      allowNull: false,
    },
    role: {
      type: Sequelize.STRING,
      allowNull: false,
      defaultValue: 'user',
    },
    createdAt: {
      type: Sequelize.DATE,
      allowNull: false,
      defaultValue: Sequelize.fn('NOW'),
    },
    updatedAt: {
      type: Sequelize.DATE,
      allowNull: false,
      defaultValue: Sequelize.fn('NOW'),
    },
  },
  {
    tableName: 'Users',
    timestamps: true,
  }
);

User.associate = (models) => {
  User.hasMany(models.Client, { foreignKey: 'owner_id', as: 'clients' });
  User.hasMany(models.Token, { foreignKey: 'user_id', as: 'tokens' });
};

return User;

