import { Model, DataTypes } from "sequelize";
import sequelize from "../config/database.js";
import { hash } from "bcryptjs";
import Logger from "../../shared/config/logger.js";

const logger = new Logger('UserModel');

class User extends Model {
  toJSON() {
    const values = { ...this.get() };
    delete values.password;
    return values;
  }

  // SOLID: Liskov Substitution Principle
  async validatePassword(password) {
    const { comparePassword } = await import('../../shared/utils/jwt.js');
    const authService = new (await import('../../shared/utils/jwt.js')).default();
    return authService.comparePassword(password, this.password);
  }
}

User.init(
  {
    id: {
      type: DataTypes.BIGINT,
      primaryKey: true,
      autoIncrement: true,
    },
    name: {
      type: DataTypes.STRING,
      validate: {
        len: [2, 100]
      }
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isAlphanumeric: true,
        len: [3, 30]
      }
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        len: [8, 100]
      }
    },
    role: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      validate: {
        min: 0,
        max: 3
      }
    },
  },
  {
    hooks: {
      async beforeCreate(user) {
        try {
          user.username = user.username.toLowerCase().trim();
          
          if (user.name) {
            user.name = user.name.trim();
          }

          // Hash password
          const authService = new (await import('../../shared/utils/jwt.js')).default();
          user.password = await authService.hashPassword(user.password);
          
          logger.info('User created successfully', { username: user.username });
        } catch (err) {
          logger.error('Error in beforeCreate hook', { error: err.message });
          throw err;
        }
      },
      beforeUpdate(user) {
        if (user.changed('username')) {
          user.username = user.username.toLowerCase().trim();
        }
        if (user.changed('name') && user.name) {
          user.name = user.name.trim();
        }
      }
    },
    sequelize: sequelize,
    tableName: "users",
    timestamps: true,
    createdAt: "createdAt",
    updatedAt: "updatedAt",
    indexes: [
      {
        unique: true,
        fields: ['username']
      },
      {
        fields: ['role']
      },
      {
        fields: ['createdAt']
      }
    ]
  }
);

export default User;