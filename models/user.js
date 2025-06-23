/**
 * ユーザーモデル
 */
module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
    // ユーザーID
    id: {
      type: DataTypes.STRING,
      primaryKey: true,
      allowNull: false
    },
    
    // ユーザー名
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        notEmpty: true
      }
    },
    
    // パスワードハッシュ
    passwordHash: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    
    // デフォルトパスワードフラグ
    isDefaultPassword: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    }
  }, {
    timestamps: true,  // createdAt, updatedAtを自動生成
    indexes: [
      { unique: true, fields: ['username'] }
    ]
  });

  return User;
};
