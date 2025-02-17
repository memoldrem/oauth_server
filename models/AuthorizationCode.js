module.exports = (sequelize, DataTypes) => {
    const AuthorizationCode = sequelize.define('AuthorizationCode', {
        authorization_code: {
            type: DataTypes.STRING,
            allowNull: false,
            primaryKey: true,
        },
        user_id: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: 'Users',
                key: 'user_id',
            },
            onUpdate: 'CASCADE',
            onDelete: 'CASCADE',
        },
        client_id: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: 'Clients',
                key: 'client_id',
            },
            onUpdate: 'CASCADE',
            onDelete: 'CASCADE',
        },
        redirect_uri: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        expires_at: {
            type: DataTypes.DATE,
            allowNull: false,
        },
        state: {
            type: DataTypes.STRING,
            allowNull: false,
        },
    }, {
        tableName: 'authorization_codes',
        timestamps: true,
    });

    AuthorizationCode.associate = (models) => {
        AuthorizationCode.belongsTo(models.User, {
            foreignKey: 'user_id',
            as: 'user',
        });
        AuthorizationCode.belongsTo(models.Client, {
            foreignKey: 'client_id',
            as: 'client',
        });
    };

    return AuthorizationCode;
};
