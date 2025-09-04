const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// Refresh Token Schema
const refreshTokenSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    userId: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    isRevoked: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const RefreshToken = mongoose.model('RefreshToken', refreshTokenSchema);

// Admin User Schema with Account Lockout
const adminUserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    failedLoginAttempts: { type: Number, default: 0 },
    lockoutUntil: { type: Date },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Virtual for checking if account is locked
adminUserSchema.virtual('isLocked').get(function () {
    return !!(this.lockoutUntil && this.lockoutUntil > Date.now());
});

// Increment failed login attempts
adminUserSchema.methods.incLoginAttempts = function () {
    // If we have a previous lock that has expired, restart at 1
    if (this.lockoutUntil && this.lockoutUntil < Date.now()) {
        return this.updateOne({
            $unset: { lockoutUntil: 1 },
            $set: { failedLoginAttempts: 1 }
        });
    }

    const updates = { $inc: { failedLoginAttempts: 1 } };

    // Lock account after 5 failed attempts for 30 minutes
    if (this.failedLoginAttempts + 1 >= 5 && !this.isLocked) {
        updates.$set = { lockoutUntil: Date.now() + 30 * 60 * 1000 }; // 30 minutes
    }

    return this.updateOne(updates);
};

// Reset failed login attempts
adminUserSchema.methods.resetLoginAttempts = function () {
    return this.updateOne({
        $unset: { failedLoginAttempts: 1, lockoutUntil: 1 },
        $set: { lastLogin: Date.now() }
    });
};

const AdminUser = mongoose.model('AdminUser', adminUserSchema);

// Password Management Class
class PasswordManager {
    static async hashPassword(password) {
        const saltRounds = 12;
        return await bcrypt.hash(password, saltRounds);
    }

    static async comparePassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }

    static validatePasswordStrength(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        const score = [
            password.length >= minLength,
            hasUpperCase,
            hasLowerCase,
            hasNumbers,
            hasSpecialChar
        ].filter(Boolean).length;

        return {
            isValid: score >= 4,
            score,
            requirements: {
                minLength: password.length >= minLength,
                hasUpperCase,
                hasLowerCase,
                hasNumbers,
                hasSpecialChar
            }
        };
    }
}

// Token Management Class
class TokenManager {
    static generateTokens(payload) {
        const accessToken = jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        const refreshToken = jwt.sign(
            { userId: payload.userId },
            process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        return { accessToken, refreshToken };
    }

    static async storeRefreshToken(token, userId) {
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        const refreshToken = new RefreshToken({
            token,
            userId,
            expiresAt
        });

        await refreshToken.save();
        return refreshToken;
    }

    static async validateRefreshToken(token) {
        const tokenDoc = await RefreshToken.findOne({
            token,
            isRevoked: false,
            expiresAt: { $gt: new Date() }
        });

        if (!tokenDoc) {
            return null;
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
            return tokenDoc;
        } catch (error) {
            await RefreshToken.updateOne({ token }, { isRevoked: true });
            return null;
        }
    }

    static async revokeRefreshToken(token) {
        await RefreshToken.updateOne({ token }, { isRevoked: true });
    }

    static async revokeAllUserTokens(userId) {
        await RefreshToken.updateMany({ userId }, { isRevoked: true });
    }

    static async cleanupExpiredTokens() {
        await RefreshToken.deleteMany({
            $or: [
                { expiresAt: { $lt: new Date() } },
                { isRevoked: true }
            ]
        });
    }
}

// Cleanup expired tokens every hour
setInterval(() => {
    TokenManager.cleanupExpiredTokens().catch(console.error);
}, 60 * 60 * 1000);

module.exports = {
    RefreshToken,
    AdminUser,
    PasswordManager,
    TokenManager
};
