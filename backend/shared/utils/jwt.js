import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

class AuthService {
  constructor() {
    this.secret = process.env.JWT_SECRET;
    this.tokenExpiry = process.env.JWT_EXPIRY;
    this.refreshSecret = process.env.JWT_REFRESH_SECRET;
    this.refreshExpiry = process.env.JWT_REFRESH_EXPIRY;
  }

  // SOLID: Interface Segregation Principle
  generateTokens(payload) {
    const accessToken = jwt.sign(
      { 
        ...payload,
        type: 'access'
      },
      this.secret,
      { expiresIn: this.tokenExpiry }
    );

    const refreshToken = jwt.sign(
      {
        ...payload,
        type: 'refresh'
      },
      this.refreshSecret,
      { expiresIn: this.refreshExpiry }
    );

    return { accessToken, refreshToken };
  }

  verifyToken(token, type = 'access') {
    try {
      const secret = type === 'refresh' ? this.refreshSecret : this.secret;
      return jwt.verify(token, secret);
    } catch (error) {
      return null;
    }
  }

  async hashPassword(password) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }

  async comparePassword(password, hashedPassword) {
    return bcrypt.compare(password, hashedPassword);
  }

  // Role-based access control
  checkPermission(userRole, requiredRole) {
    const roles = {
      0: 'user',     // Regular user
      1: 'admin',    // Admin
      2: 'printer',  // Printer
      3: 'data_entry' // Data entry
    };

    const roleHierarchy = {
      user: 0,
      data_entry: 3,
      printer: 2,
      admin: 1
    };

    const userRoleName = roles[userRole] || 'user';
    const requiredRoleName = typeof requiredRole === 'number' 
      ? roles[requiredRole] 
      : requiredRole;

    return roleHierarchy[userRoleName] >= roleHierarchy[requiredRoleName];
  }

  // Generate middleware for role-based access
  requireRole(requiredRole) {
    return (req, res, next) => {
      const token = req.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return res.status(401).json({ error: 'No token provided' });
      }

      const decoded = this.verifyToken(token);
      
      if (!decoded) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      if (!this.checkPermission(decoded.role, requiredRole)) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }

      req.user = decoded;
      next();
    };
  }
}

export default AuthService;