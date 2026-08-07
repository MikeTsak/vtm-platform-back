const swaggerAutogen = require('swagger-autogen')({ openapi: '3.0.0' });
const path = require('path');

const doc = {
  info: {
    title: 'Erebus Portal API',
    version: '1.0.0',
    description: 'API documentation for the Vampire: The Masquerade RPG portal.',
  },
  servers: [
    {
      url: 'http://localhost:3001',
      description: 'API Server',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    '@schemas': {
      User: {
        type: 'object',
        properties: {
          id: { type: 'integer', description: 'User ID' },
          email: { type: 'string', format: 'email', description: 'User email address' },
          display_name: { type: 'string', description: 'User display name' },
          role: { type: 'string', enum: ['user', 'admin'], description: 'User role' },
        },
      },
      Character: {
        type: 'object',
        properties: {
          id: { type: 'integer', description: 'Character ID' },
          user_id: { type: 'integer', description: 'ID of the user who owns this character' },
          name: { type: 'string', description: 'Character name' },
          clan: { type: 'string', description: 'Vampire clan' },
          sheet: { type: 'object', description: 'Character sheet data (JSON)' },
          xp: { type: 'integer', description: 'Experience points' },
        },
      },
      Error: {
        type: 'object',
        properties: {
          error: { type: 'string', description: 'Error message' },
        },
      },
    }
  },
  security: [{ bearerAuth: [] }],
};

const outputFile = './swagger_output.json';
const routes = [
  './server.fastify.js',
  './routes/auth.js',
  './routes/characters.js',
  './routes/dashboard.fastify.js',
  './routes/dashboard.js',
  './routes/index.fastify.js',
  './routes/index.js',
  './routes/users.fastify.js',
  './routes/users.js'
];

// Generate swagger_output.json
swaggerAutogen(outputFile, routes, doc).then(() => {
    console.log('Swagger documentation generated successfully!');
});
