import Joi from 'joi';
import { escape, escapeHtml } from 'validator';

class InputValidator {
  // SOLID: Open/Closed Principle
  static validateUserInput(data) {
    const schema = Joi.object({
      name: Joi.string()
        .min(2)
        .max(100)
        .pattern(/^[a-zA-Z\s]+$/)
        .required(),
      username: Joi.string()
        .alphanum()
        .min(3)
        .max(30)
        .required(),
      password: Joi.string()
        .min(8)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .required(),
      role: Joi.number()
        .integer()
        .min(0)
        .max(3)
        .default(0)
    });

    return schema.validate(data, { abortEarly: false });
  }

  static sanitizeInput(input) {
    if (typeof input === 'string') {
      // Prevent XSS
      return escapeHtml(escape(input));
    }
    return input;
  }

  static validateCompanyInput(data) {
    const schema = Joi.object({
      name: Joi.string()
        .min(2)
        .max(200)
        .required(),
      description: Joi.string()
        .max(1000)
        .allow('', null)
    });

    return schema.validate(data, { abortEarly: false });
  }

  static validatePagination(params) {
    const schema = Joi.object({
      page: Joi.number()
        .integer()
        .min(1)
        .default(1),
      limit: Joi.number()
        .integer()
        .min(1)
        .max(100)
        .default(10),
      cursor: Joi.string()
        .allow('', null)
    });

    return schema.validate(params, { abortEarly: false });
  }
}

export default InputValidator;