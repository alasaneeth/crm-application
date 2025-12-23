import { Sequelize } from 'sequelize';
import Logger from '../../shared/config/logger.js';

const logger = new Logger('database');

const sequelize = new Sequelize(
  process.env.DB_NAME || 'auth_service',
  process.env.DB_USER || 'postgres',
  process.env.DB_PASSWORD || 'password',
  {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    dialect: 'postgres',
    logging: (msg) => logger.debug(msg),
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    },
    dialectOptions: process.env.DB_SSL === 'true' ? {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    } : {}
  }
);

// Test connection
sequelize.authenticate()
  .then(() => logger.info('Database connection established'))
  .catch(err => {
    logger.error('Unable to connect to database:', err);
    process.exit(1);
  });

export default sequelize;