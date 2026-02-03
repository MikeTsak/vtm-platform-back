// swagger.config.js
// Swagger/OpenAPI configuration for the Erebus Portal API

const swaggerJsdoc = require('swagger-jsdoc');

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Erebus Portal API',
      version: '1.0.0',
      description: 'API documentation for the Vampire: The Masquerade RPG portal. This API provides endpoints for user authentication, character management, and game interactions.',
      contact: {
        name: 'API Support',
        url: 'https://vtm.back.miketsak.gr',
      },
    },
    servers: [
      {
        url: 'http://localhost:3001',
        description: 'Development Server',
      },
      {
        url: 'https://vtm.back.miketsak.gr',
        description: 'Production Server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter your JWT token in the format: Bearer <token>',
        },
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: {
              type: 'integer',
              description: 'User ID',
            },
            email: {
              type: 'string',
              format: 'email',
              description: 'User email address',
            },
            display_name: {
              type: 'string',
              description: 'User display name',
            },
            role: {
              type: 'string',
              enum: ['user', 'admin'],
              description: 'User role',
            },
          },
        },
        Character: {
          type: 'object',
          properties: {
            id: {
              type: 'integer',
              description: 'Character ID',
            },
            user_id: {
              type: 'integer',
              description: 'ID of the user who owns this character',
            },
            name: {
              type: 'string',
              description: 'Character name',
            },
            clan: {
              type: 'string',
              description: 'Vampire clan',
            },
            sheet: {
              type: 'object',
              description: 'Character sheet data (JSON)',
            },
            xp: {
              type: 'integer',
              description: 'Experience points',
            },
          },
        },
        Error: {
          type: 'object',
          properties: {
            error: {
              type: 'string',
              description: 'Error message',
            },
          },
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  // This looks for @swagger comments in the server.js file
  apis: ['./server.js'],
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

module.exports = swaggerSpec;
