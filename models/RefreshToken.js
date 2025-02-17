module.exports = (sequelize, DataTypes) => {
    const RefreshToken = sequelize.define('RefreshToken', {
        refresh_token: { type: DataTypes.STRING, primaryKey: true },
        user_id: { type: DataTypes.INTEGER, allowNull: false },
        client_id: { type: DataTypes.INTEGER, allowNull: false },
        expires_at: { type: DataTypes.DATE, allowNull: false },
        is_revoked: { type: DataTypes.BOOLEAN, defaultValue: false },
    }, {
        tableName: 'refresh_tokens',
        timestamps: true, 
    });

    RefreshToken.associate = (models) => {
        RefreshToken.belongsTo(models.User, { foreignKey: 'user_id', as: 'user' });
        RefreshToken.belongsTo(models.Client, { foreignKey: 'client_id', as: 'client' });
    };
  
    return RefreshToken;
};
