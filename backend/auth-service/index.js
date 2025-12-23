import express from 'express';
import { ApolloServer } from 'apollo-server-express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { gql } from 'graphql-tag';
import sequelize from './config/database.js';
import User from './models/User.js';
import Logger from '../shared/config/logger.js';
import AuthService from '../shared/utils/jwt.js';
import InputValidator from '../shared/utils/validation.js';
import MessageQueue from './services/MessageQueue.js';
import UserDataSource from './datasources/UserDataSource.js';

const logger = new Logger('auth-service');
const authService = new AuthService();

// Database connection
await sequelize.authenticate();
logger.info('Database connected successfully');

// GraphQL Schema
const typeDefs = gql`
  type User {
    id: ID!
    name: String
    username: String!
    role: Int!
    createdAt: String!
    updatedAt: String!
  }

  type AuthPayload {
    accessToken: String!
    refreshToken: String!
    user: User!
  }

  type PaginatedUsers {
    users: [User!]!
    totalCount: Int!
    pageInfo: PageInfo!
  }

  type PageInfo {
    hasNextPage: Boolean!
    hasPreviousPage: Boolean!
    startCursor: String
    endCursor: String
  }

  type Query {
    # Get current user profile
    me: User! @auth(requires: USER)
    
    # Get user by ID (admin only)
    user(id: ID!): User @auth(requires: ADMIN)
    
    # Get all users with pagination
    users(
      page: Int = 1
      limit: Int = 10
      cursor: String
    ): PaginatedUsers! @auth(requires: ADMIN)
    
    # Search users
    searchUsers(
      query: String!
      page: Int = 1
      limit: Int = 10
    ): PaginatedUsers! @auth(requires: ADMIN)
  }

  type Mutation {
    # Register new user
    register(
      name: String!
      username: String!
      password: String!
      role: Int = 0
    ): AuthPayload!
    
    # Login
    login(
      username: String!
      password: String!
    ): AuthPayload!
    
    # Refresh token
    refreshToken(refreshToken: String!): AuthPayload!
    
    # Update user profile
    updateProfile(
      name: String
      password: String
    ): User! @auth(requires: USER)
    
    # Update user role (admin only)
    updateUserRole(
      userId: ID!
      role: Int!
    ): User! @auth(requires: ADMIN)
    
    # Delete user (admin only)
    deleteUser(userId: ID!): Boolean! @auth(requires: ADMIN)
  }
`;

// Resolvers (Implementing logic at endpoints)
const resolvers = {
  Query: {
    me: async (_, __, { dataSources, user }) => {
      try {
        logger.info('Fetching user profile', { userId: user.id });
        return await dataSources.users.getUserById(user.id);
      } catch (error) {
        logger.error('Error fetching user profile', { error: error.message, userId: user.id });
        throw new Error('Failed to fetch user profile');
      }
    },

    user: async (_, { id }, { dataSources, user }) => {
      logger.info('Fetching user by ID', { requestedId: id, requesterId: user.id });
      return await dataSources.users.getUserById(id);
    },

    users: async (_, { page, limit, cursor }, { dataSources }) => {
      // Input validation
      const { error } = InputValidator.validatePagination({ page, limit, cursor });
      if (error) {
        throw new Error(`Invalid pagination parameters: ${error.details.map(d => d.message).join(', ')}`);
      }

      logger.info('Fetching paginated users', { page, limit });
      return await dataSources.users.getPaginatedUsers({ page, limit, cursor });
    },

    searchUsers: async (_, { query, page, limit }, { dataSources }) => {
      // Input sanitization
      const sanitizedQuery = InputValidator.sanitizeInput(query);
      
      logger.info('Searching users', { query: sanitizedQuery, page, limit });
      return await dataSources.users.searchUsers({ query: sanitizedQuery, page, limit });
    }
  },

  Mutation: {
    register: async (_, { name, username, password, role }, { dataSources }) => {
      // Input validation
      const { error, value } = InputValidator.validateUserInput({
        name,
        username,
        password,
        role
      });

      if (error) {
        throw new Error(`Validation failed: ${error.details.map(d => d.message).join(', ')}`);
      }

      logger.info('User registration attempt', { username: value.username });

      // Check if user exists
      const existingUser = await dataSources.users.getUserByUsername(value.username);
      if (existingUser) {
        throw new Error('Username already exists');
      }

      // Create user
      const user = await dataSources.users.createUser(value);

      // Generate tokens
      const tokens = authService.generateTokens({
        id: user.id,
        username: user.username,
        role: user.role
      });

      // Send welcome email via message queue
      await MessageQueue.publish('user.registered', {
        userId: user.id,
        email: user.username,
        name: user.name
      });

      logger.info('User registered successfully', { userId: user.id });

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user
      };
    },

    login: async (_, { username, password }, { dataSources }) => {
      // Input sanitization
      const sanitizedUsername = InputValidator.sanitizeInput(username);
      
      logger.info('Login attempt', { username: sanitizedUsername });

      // Find user
      const user = await dataSources.users.getUserByUsername(sanitizedUsername);
      if (!user) {
        throw new Error('Invalid credentials');
      }

      // Verify password
      const isValidPassword = await authService.comparePassword(password, user.password);
      if (!isValidPassword) {
        throw new Error('Invalid credentials');
      }

      // Generate tokens
      const tokens = authService.generateTokens({
        id: user.id,
        username: user.username,
        role: user.role
      });

      // Log login event
      await MessageQueue.publish('user.logged_in', {
        userId: user.id,
        timestamp: new Date().toISOString()
      });

      logger.info('User logged in successfully', { userId: user.id });

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: user.toJSON()
      };
    },

    refreshToken: async (_, { refreshToken }) => {
      logger.info('Token refresh attempt');

      const decoded = authService.verifyToken(refreshToken, 'refresh');
      if (!decoded) {
        throw new Error('Invalid refresh token');
      }

      // Generate new tokens
      const tokens = authService.generateTokens({
        id: decoded.id,
        username: decoded.username,
        role: decoded.role
      });

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        user: {
          id: decoded.id,
          username: decoded.username,
          role: decoded.role
        }
      };
    },

    updateProfile: async (_, { name, password }, { dataSources, user }) => {
      const updates = {};

      if (name) {
        updates.name = InputValidator.sanitizeInput(name);
      }

      if (password) {
        // Validate password strength
        const { error } = InputValidator.validateUserInput({ password });
        if (error) {
          throw new Error(`Password validation failed: ${error.details.map(d => d.message).join(', ')}`);
        }
        updates.password = await authService.hashPassword(password);
      }

      logger.info('Updating user profile', { userId: user.id, updates: Object.keys(updates) });

      const updatedUser = await dataSources.users.updateUser(user.id, updates);
      
      // Notify about profile update
      await MessageQueue.publish('user.profile_updated', {
        userId: user.id,
        updates: Object.keys(updates)
      });

      return updatedUser;
    },

    updateUserRole: async (_, { userId, role }, { dataSources, user }) => {
      logger.info('Updating user role', { 
        targetUserId: userId, 
        newRole: role, 
        adminId: user.id 
      });

      // Validate role
      if (role < 0 || role > 3) {
        throw new Error('Invalid role specified');
      }

      const updatedUser = await dataSources.users.updateUser(userId, { role });
      
      // Log role change
      await MessageQueue.publish('user.role_changed', {
        userId,
        newRole: role,
        changedBy: user.id,
        timestamp: new Date().toISOString()
      });

      return updatedUser;
    },

    deleteUser: async (_, { userId }, { dataSources, user }) => {
      logger.warn('Deleting user', { 
        targetUserId: userId, 
        adminId: user.id 
      });

      // Prevent self-deletion
      if (userId === user.id) {
        throw new Error('Cannot delete your own account');
      }

      const result = await dataSources.users.deleteUser(userId);
      
      if (result) {
        await MessageQueue.publish('user.deleted', {
          userId,
          deletedBy: user.id,
          timestamp: new Date().toISOString()
        });
      }

      return result;
    }
  },

  User: {
    // Field-level resolver for data transformation
    createdAt: (user) => user.createdAt.toISOString(),
    updatedAt: (user) => user.updatedAt.toISOString()
  }
};

// Apollo Server setup
const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: ({ req }) => {
    // Extract token from headers
    const token = req.headers.authorization?.split(' ')[1];
    let user = null;

    if (token) {
      const decoded = authService.verifyToken(token);
      if (decoded) {
        user = decoded;
      }
    }

    return {
      user,
      dataSources: {
        users: new UserDataSource()
      }
    };
  },
  formatError: (error) => {
    logger.error('GraphQL Error', {
      message: error.message,
      path: error.path,
      locations: error.locations
    });

    // Don't expose internal errors in production
    if (process.env.NODE_ENV === 'production' && !error.originalError?.expose) {
      return new Error('Internal server error');
    }

    return error;
  }
});

// Express app setup
const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false
}));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/graphql', limiter);

// Apply Apollo middleware
await server.start();
server.applyMiddleware({ app, path: '/graphql' });

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'auth-service',
    timestamp: new Date().toISOString()
  });
});

// Versioning endpoint
app.get('/api/v1/health', (req, res) => {
  res.json({
    version: '1.0.0',
    status: 'healthy'
  });
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => {
  logger.info(`Authentication service running on http://localhost:${PORT}/graphql`);
});