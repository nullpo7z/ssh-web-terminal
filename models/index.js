const { Sequelize } = require('sequelize');
const path = require('path');
const fs = require('fs');

// データベース設定
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, '../db/ssh_web_terminal.sqlite'),
  logging: false,
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  }
});

// データベースオブジェクト
const db = {
  sequelize,
  Sequelize
};

// モデルの自動読み込み
fs.readdirSync(__dirname)
  .filter(file => file !== 'index.js' && file.endsWith('.js'))
  .forEach(file => {
    const model = require(path.join(__dirname, file))(sequelize, Sequelize.DataTypes);
    db[model.name] = model;
  });

// モデル間の関連付け
Object.keys(db).forEach(modelName => {
  if (db[modelName].associate) db[modelName].associate(db);
});

module.exports = db;
