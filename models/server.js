/**
 * サーバーモデル
 */
module.exports = (sequelize, DataTypes) => {
  const Server = sequelize.define('Server', {
    // サーバーID
    id: {
      type: DataTypes.STRING,
      primaryKey: true,
      allowNull: false
    },
    
    // サーバー名
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    
    // ホスト名/IPアドレス
    host: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true,
        isValidHost(value) {
          const hostRegex = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
          if (!hostRegex.test(value)) {
            throw new Error('Invalid host format');
          }
        }
      }
    },
    
    // SSHユーザー名
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    
    // 暗号化された秘密鍵
    privateKey: {
      type: DataTypes.TEXT,
      allowNull: false,
      validate: {
        notEmpty: true
      }
    }
  }, {
    timestamps: true,  // createdAt, updatedAtを自動生成
    indexes: [
      { fields: ['name'] }
    ]
  });

  return Server;
};
