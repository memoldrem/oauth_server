module.exports = (sequelize, DataTypes) => {
    const UserClientConsent = sequelize.define('UserClientConsent', {
        user_id: {
            type: DataTypes.INTEGER,
            allowNull: false
        },
        client_id: {
            type: DataTypes.INTEGER,
            allowNull: false
        },
        consent_granted: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false
        }
    }, {
        tableName: 'user_client_consents',
        timestamps: true
    });

    UserClientConsent.associate = (models) => {
        UserClientConsent.belongsTo(models.User, { foreignKey: 'user_id', as: 'user' });
        UserClientConsent.belongsTo(models.Client, { foreignKey: 'client_id', as: 'client' });
    };

    return UserClientConsent;
};