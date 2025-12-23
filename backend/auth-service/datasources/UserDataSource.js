import DataLoader from 'dataloader';
import User from '../models/User.js';
import Logger from '../../shared/config/logger.js';

const logger = new Logger('UserDataSource');

class UserDataSource {
  constructor() {
    // SOLID: Dependency Inversion Principle
    this.userLoader = new DataLoader(async (userIds) => {
      logger.debug('Batch loading users', { userIds });
      const users = await User.findAll({
        where: {
          id: userIds
        }
      });

      const userMap = {};
      users.forEach(user => {
        userMap[user.id] = user;
      });

      return userIds.map(id => userMap[id] || null);
    }, { cache: true });

    this.usernameLoader = new DataLoader(async (usernames) => {
      logger.debug('Batch loading users by username', { usernames });
      const users = await User.findAll({
        where: {
          username: usernames
        }
      });

      const userMap = {};
      users.forEach(user => {
        userMap[user.username] = user;
      });

      return usernames.map(username => userMap[username] || null);
    }, { cache: true });
  }

  // Get user by ID with caching
  async getUserById(id) {
    try {
      return await this.userLoader.load(id);
    } catch (error) {
      logger.error('Error getting user by ID', { id, error: error.message });
      throw error;
    }
  }

  // Get user by username with caching
  async getUserByUsername(username) {
    try {
      return await this.usernameLoader.load(username.toLowerCase());
    } catch (error) {
      logger.error('Error getting user by username', { username, error: error.message });
      throw error;
    }
  }

  // Create new user
  async createUser(userData) {
    try {
      const user = await User.create(userData);
      // Clear relevant caches
      this.userLoader.clear(user.id);
      this.usernameLoader.clear(user.username);
      return user;
    } catch (error) {
      logger.error('Error creating user', { error: error.message });
      throw error;
    }
  }

  // Update user
  async updateUser(id, updates) {
    try {
      const [affectedCount, updatedUsers] = await User.update(updates, {
        where: { id },
        returning: true
      });

      if (affectedCount === 0) {
        throw new Error('User not found');
      }

      const updatedUser = updatedUsers[0];
      
      // Clear caches
      this.userLoader.clear(id);
      this.usernameLoader.clear(updatedUser.username);

      return updatedUser;
    } catch (error) {
      logger.error('Error updating user', { id, error: error.message });
      throw error;
    }
  }

  // Delete user
  async deleteUser(id) {
    try {
      const user = await User.findByPk(id);
      if (!user) {
        return false;
      }

      await user.destroy();
      
      // Clear caches
      this.userLoader.clear(id);
      this.usernameLoader.clear(user.username);

      return true;
    } catch (error) {
      logger.error('Error deleting user', { id, error: error.message });
      throw error;
    }
  }

  // Get paginated users (Cursor-based pagination)
  async getPaginatedUsers({ page = 1, limit = 10, cursor = null }) {
    try {
      const offset = (page - 1) * limit;

      // For cursor-based pagination
      let where = {};
      if (cursor) {
        const cursorDate = new Date(cursor);
        where.createdAt = { [Sequelize.Op.lt]: cursorDate };
      }

      const { count, rows } = await User.findAndCountAll({
        where,
        limit: limit + 1, // Get one extra to check if there's next page
        offset: cursor ? 0 : offset,
        order: [['createdAt', 'DESC']]
      });

      const hasNextPage = rows.length > limit;
      const users = hasNextPage ? rows.slice(0, limit) : rows;

      const startCursor = users.length > 0 ? users[0].createdAt.toISOString() : null;
      const endCursor = users.length > 0 ? users[users.length - 1].createdAt.toISOString() : null;

      return {
        users,
        totalCount: count,
        pageInfo: {
          hasNextPage,
          hasPreviousPage: page > 1,
          startCursor,
          endCursor
        }
      };
    } catch (error) {
      logger.error('Error getting paginated users', { page, limit, error: error.message });
      throw error;
    }
  }

  // Search users
  async searchUsers({ query, page = 1, limit = 10 }) {
    try {
      const offset = (page - 1) * limit;
      
      const { Op } = await import('sequelize');
      const where = {
        [Op.or]: [
          { name: { [Op.iLike]: `%${query}%` } },
          { username: { [Op.iLike]: `%${query}%` } }
        ]
      };

      const { count, rows } = await User.findAndCountAll({
        where,
        limit,
        offset,
        order: [['createdAt', 'DESC']]
      });

      return {
        users: rows,
        totalCount: count,
        pageInfo: {
          hasNextPage: count > offset + limit,
          hasPreviousPage: page > 1,
          startCursor: rows.length > 0 ? rows[0].createdAt.toISOString() : null,
          endCursor: rows.length > 0 ? rows[rows.length - 1].createdAt.toISOString() : null
        }
      };
    } catch (error) {
      logger.error('Error searching users', { query, error: error.message });
      throw error;
    }
  }
}

export default UserDataSource;