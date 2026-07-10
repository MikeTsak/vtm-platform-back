const { z } = require('zod');
const { log } = require('../logger');

/**
 * Express middleware to validate request bodies, query params, or params.
 * @param {z.ZodSchema} schema The Zod schema to validate against
 * @param {'body' | 'query' | 'params'} property The request property to validate
 */
const validateRequest = (schema, property = 'body') => (req, res, next) => {
  try {
    const validData = schema.parse(req[property]);
    req[property] = validData; // Override with validated (and optionally coerced) data
    next();
  } catch (error) {
    if (error instanceof z.ZodError) {
      log.warn(`Validation error on ${property}`, { errors: error.errors });
      return res.status(400).json({
        error: 'Validation Error',
        details: error.errors.map(e => ({
          path: e.path.join('.'),
          message: e.message
        }))
      });
    }
    next(error);
  }
};

module.exports = { validateRequest };
