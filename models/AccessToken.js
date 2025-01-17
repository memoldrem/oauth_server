module.exports = (sequelize, DataTypes) => {
    const AccessToken = sequelize.define('AccessToken', {
        access_token: { type: DataTypes.STRING, primaryKey: true },
        user_id: { type: DataTypes.INTEGER, allowNull: false },
        client_id: { type: DataTypes.INTEGER, allowNull: false },
        expires_at: { type: DataTypes.DATE, allowNull: false },
    }, { 
        timestamps: true, 
    });
  
    AccessToken.associate = (models) => {
        AccessToken.belongsTo(models.User, { foreignKey: 'user_id', as: 'user' });
        AccessToken.belongsTo(models.Client, { foreignKey: 'client_id', as: 'client' });
    };
  
    return AccessToken;
};
