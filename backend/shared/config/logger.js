import winston from 'winston';
import path from 'path';

class Logger {
  constructor(serviceName) {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: serviceName },
      transports: [
        new winston.transports.File({ 
          filename: path.join('logs', 'error.log'), 
          level: 'error' 
        }),
        new winston.transports.File({ 
          filename: path.join('logs', 'combined.log') 
        }),
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ]
    });
  }

  // SOLID: Single Responsibility Principle
  log(level, message, meta = {}) {
    this.logger.log(level, message, meta);
  }

  info(message, meta = {}) {
    this.log('info', message, meta);
  }

  error(message, meta = {}) {
    this.log('error', message, meta);
  }

  warn(message, meta = {}) {
    this.log('warn', message, meta);
  }

  debug(message, meta = {}) {
    this.log('debug', message, meta);
  }
}

export default Logger;