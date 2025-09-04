const mongoose = require('mongoose');

// Role-Based Access Control System
const roleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  permissions: [
    {
      resource: String, // 'contacts', 'logs', 'users', 'system'
      actions: [String], // 'read', 'write', 'delete', 'admin'
    },
  ],
  level: { type: Number, required: true }, // 1=viewer, 2=editor, 3=admin, 4=super-admin
  createdAt: { type: Date, default: Date.now },
});

// Check if Role model already exists to prevent OverwriteModelError
const Role = mongoose.models.Role || mongoose.model('Role', roleSchema);

// Enhanced Admin User with RBAC
const adminUserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  passwordHash: { type: String, required: true },
  roleId: { type: mongoose.Schema.Types.ObjectId, ref: 'Role', required: true },

  // Account security
  failedLoginAttempts: { type: Number, default: 0 },
  lockoutUntil: { type: Date },
  lastLogin: { type: Date },
  lastLoginIP: { type: String },

  // Geographic restrictions
  allowedCountries: [{ type: String, default: ['IN'] }], // ISO country codes
  allowedIPs: [String], // Specific IP whitelist

  // Session management
  activeSessions: [
    {
      tokenId: String,
      ip: String,
      userAgent: String,
      country: String,
      createdAt: { type: Date, default: Date.now },
    },
  ],

  // Audit trail
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastModified: { type: Date, default: Date.now },
});

// Virtual for checking if account is locked
adminUserSchema.virtual('isLocked').get(function () {
  return !!(this.lockoutUntil && this.lockoutUntil > Date.now());
});

// Increment failed login attempts
adminUserSchema.methods.incLoginAttempts = function () {
  if (this.lockoutUntil && this.lockoutUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockoutUntil: 1 },
      $set: { failedLoginAttempts: 1 },
    });
  }

  const updates = { $inc: { failedLoginAttempts: 1 } };

  if (this.failedLoginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockoutUntil: Date.now() + 30 * 60 * 1000 };
  }

  return this.updateOne(updates);
};

// Reset failed login attempts
adminUserSchema.methods.resetLoginAttempts = function () {
  return this.updateOne({
    $unset: { failedLoginAttempts: 1, lockoutUntil: 1 },
    $set: { lastLogin: Date.now() },
  });
};

// Check if AdminUser model already exists
const AdminUser = mongoose.models.AdminUser || mongoose.model('AdminUser', adminUserSchema);

// User Rate Limiting Schema
const userRateLimitSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  endpoint: { type: String, required: true },
  count: { type: Number, default: 1 },
  windowStart: { type: Date, default: Date.now },
  resetAt: { type: Date, required: true },
});

const UserRateLimit = mongoose.models.UserRateLimit || mongoose.model('UserRateLimit', userRateLimitSchema);

// RBAC Manager Class
class RBACManager {
  static async initializeRoles() {
    try {
      const existingRoles = await Role.countDocuments();
      if (existingRoles > 0) {
        console.log('✅ RBAC roles already initialized');
        return;
      }

      const defaultRoles = [
        {
          name: 'viewer',
          level: 1,
          permissions: [
            { resource: 'contacts', actions: ['read'] },
            { resource: 'system', actions: ['read'] },
          ],
        },
        {
          name: 'editor',
          level: 2,
          permissions: [
            { resource: 'contacts', actions: ['read', 'write'] },
            { resource: 'system', actions: ['read'] },
          ],
        },
        {
          name: 'admin',
          level: 3,
          permissions: [
            { resource: 'contacts', actions: ['read', 'write', 'delete'] },
            { resource: 'logs', actions: ['read', 'write'] },
            { resource: 'system', actions: ['read', 'write'] },
          ],
        },
        {
          name: 'super-admin',
          level: 4,
          permissions: [
            { resource: 'contacts', actions: ['read', 'write', 'delete', 'admin'] },
            { resource: 'logs', actions: ['read', 'write', 'delete', 'admin'] },
            { resource: 'users', actions: ['read', 'write', 'delete', 'admin'] },
            { resource: 'system', actions: ['read', 'write', 'delete', 'admin'] },
          ],
        },
      ];

      await Role.insertMany(defaultRoles);
      console.log('✅ RBAC roles initialized successfully');
    } catch (error) {
      console.error('❌ Failed to initialize RBAC roles:', error.message);
    }
  }

  static async getUserRole(userId) {
    try {
      const user = await AdminUser.findById(userId).populate('roleId');
      return user?.roleId || null;
    } catch (error) {
      console.error('❌ Error getting user role:', error.message);
      return null;
    }
  }

  static async checkPermission(userId, resource, action) {
    try {
      const role = await this.getUserRole(userId);
      if (!role) {
        return false;
      }

      const permission = role.permissions.find((p) => p.resource === resource);
      return permission && permission.actions.includes(action);
    } catch (error) {
      console.error('❌ Error checking permission:', error.message);
      return false;
    }
  }

  static requirePermission(resource, action) {
    return async (req, res, next) => {
      try {
        const userId = req.user?.userId;
        if (!userId) {
          return res.status(401).json({
            message: 'Authentication required',
            success: false,
          });
        }

        const hasPermission = await this.checkPermission(userId, resource, action);
        if (!hasPermission) {
          return res.status(403).json({
            message: 'Insufficient permissions',
            success: false,
            required: `${resource}:${action}`,
          });
        }

        next();
      } catch (error) {
        console.error('❌ Permission check error:', error.message);
        res.status(500).json({
          message: 'Permission check failed',
          success: false,
        });
      }
    };
  }

  static async createUser(userData) {
    try {
      const defaultRole = await Role.findOne({ name: 'viewer' });
      if (!defaultRole) {
        throw new Error('Default role not found');
      }

      const user = new AdminUser({
        ...userData,
        roleId: defaultRole._id,
      });

      await user.save();
      return user;
    } catch (error) {
      console.error('❌ Error creating user:', error.message);
      throw error;
    }
  }

  static async updateUserRole(userId, roleName) {
    try {
      const role = await Role.findOne({ name: roleName });
      if (!role) {
        throw new Error('Role not found');
      }

      await AdminUser.findByIdAndUpdate(userId, { roleId: role._id });
      return true;
    } catch (error) {
      console.error('❌ Error updating user role:', error.message);
      return false;
    }
  }
}

module.exports = {
  Role,
  AdminUser,
  UserRateLimit,
  RBACManager,
};
