const geoip = require('geoip-lite');
const crypto = require('crypto');
const { AdminUser } = require('./logging');

// Geo-IP Security Manager
class GeoSecurityManager {
    constructor() {
        this.allowedCountries = process.env.ALLOWED_COUNTRIES?.split(',') || ['IN'];
        this.blockedCountries = process.env.BLOCKED_COUNTRIES?.split(',') || ['CN', 'RU', 'KP'];
        this.suspiciousCountries = ['IR', 'SY', 'AF']; // Additional monitoring
    }

    checkGeoLocation(ip) {
        const geo = geoip.lookup(ip);

        if (!geo) {
            return {
                allowed: false,
                reason: 'Unable to determine location',
                country: 'UNKNOWN'
            };
        }

        const country = geo.country;

        // Check blocked countries first
        if (this.blockedCountries.includes(country)) {
            return {
                allowed: false,
                reason: `Access blocked from ${country}`,
                country,
                geo
            };
        }

        // Check allowed countries for admin access
        if (!this.allowedCountries.includes(country)) {
            return {
                allowed: false,
                reason: `Admin access restricted to: ${this.allowedCountries.join(', ')}`,
                country,
                geo
            };
        }

        return {
            allowed: true,
            country,
            geo,
            suspicious: this.suspiciousCountries.includes(country)
        };
    }

    geoRestrictMiddleware(req, res, next) {
        const clientIP = req.ip || req.connection.remoteAddress;
        const geoCheck = this.checkGeoLocation(clientIP);

        if (!geoCheck.allowed) {
            console.log('🌍 Geo-blocked access attempt:', {
                ip: clientIP,
                country: geoCheck.country,
                reason: geoCheck.reason,
                userAgent: req.get('User-Agent'),
                timestamp: new Date().toISOString()
            });

            return res.status(403).json({
                message: 'Access denied from your location',
                success: false,
                code: 'GEO_BLOCKED'
            });
        }

        // Log suspicious countries but allow access
        if (geoCheck.suspicious) {
            console.log('🚨 Suspicious country access:', {
                ip: clientIP,
                country: geoCheck.country,
                path: req.path,
                userAgent: req.get('User-Agent')
            });
        }

        req.geoInfo = geoCheck;
        next();
    }
}

// HMAC Request Signing
class RequestSigner {
    constructor() {
        this.signingKey = process.env.HMAC_SIGNING_KEY || crypto.randomBytes(32).toString('hex');
    }

    generateSignature(method, path, body, timestamp, nonce) {
        const payload = `${method}|${path}|${JSON.stringify(body)}|${timestamp}|${nonce}`;
        return crypto.createHmac('sha256', this.signingKey).update(payload).digest('hex');
    }

    verifySignature(req, res, next) {
        const signature = req.headers['x-signature'];
        const timestamp = req.headers['x-timestamp'];
        const nonce = req.headers['x-nonce'];

        if (!signature || !timestamp || !nonce) {
            return res.status(401).json({
                message: 'Request signature required',
                success: false,
                required: ['x-signature', 'x-timestamp', 'x-nonce']
            });
        }

        // Check timestamp (prevent replay attacks)
        const now = Date.now();
        const requestTime = parseInt(timestamp);
        const timeDiff = Math.abs(now - requestTime);

        if (timeDiff > 300000) { // 5 minutes tolerance
            return res.status(401).json({
                message: 'Request timestamp expired',
                success: false
            });
        }

        // Verify signature
        const expectedSignature = this.generateSignature(
            req.method,
            req.path,
            req.body,
            timestamp,
            nonce
        );

        if (signature !== expectedSignature) {
            console.log('🚨 Invalid request signature:', {
                ip: req.ip,
                path: req.path,
                expected: expectedSignature,
                received: signature
            });

            return res.status(401).json({
                message: 'Invalid request signature',
                success: false
            });
        }

        req.signatureVerified = true;
        next();
    }

    // Helper method to generate signature for clients
    static generateClientSignature(method, path, body, signingKey) {
        const timestamp = Date.now().toString();
        const nonce = crypto.randomBytes(16).toString('hex');

        const payload = `${method}|${path}|${JSON.stringify(body)}|${timestamp}|${nonce}`;
        const signature = crypto.createHmac('sha256', signingKey).update(payload).digest('hex');

        return {
            signature,
            timestamp,
            nonce
        };
    }
}

// Advanced Rate Limiting per User Token
class TokenRateLimiter {
    constructor() {
        this.userLimits = new Map(); // userId -> { requests: [], blocked: false }
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000); // Cleanup every minute
    }

    checkUserLimit(userId, maxRequests = 50, windowMs = 15 * 60 * 1000) {
        const now = Date.now();
        const windowStart = now - windowMs;

        const userData = this.userLimits.get(userId) || { requests: [], blocked: false, blockUntil: 0 };

        // Check if user is blocked
        if (userData.blocked && userData.blockUntil > now) {
            return {
                allowed: false,
                retryAfter: Math.ceil((userData.blockUntil - now) / 1000)
            };
        }

        // Remove old requests
        userData.requests = userData.requests.filter(timestamp => timestamp > windowStart);

        // Check limit
        if (userData.requests.length >= maxRequests) {
            userData.blocked = true;
            userData.blockUntil = now + windowMs;
            this.userLimits.set(userId, userData);

            return {
                allowed: false,
                retryAfter: Math.ceil(windowMs / 1000)
            };
        }

        // Add current request
        userData.requests.push(now);
        userData.blocked = false;
        this.userLimits.set(userId, userData);

        return {
            allowed: true,
            remaining: maxRequests - userData.requests.length
        };
    }

    middleware(maxRequests = 50, windowMs = 15 * 60 * 1000) {
        return (req, res, next) => {
            if (!req.user?.userId) {
                return next(); // Skip for unauthenticated requests
            }

            const result = this.checkUserLimit(req.user.userId, maxRequests, windowMs);

            if (!result.allowed) {
                return res.status(429).json({
                    message: 'User rate limit exceeded',
                    success: false,
                    retryAfter: result.retryAfter,
                    type: 'USER_RATE_LIMIT'
                });
            }

            res.set('X-User-RateLimit-Remaining', result.remaining);
            next();
        };
    }

    cleanup() {
        const now = Date.now();
        for (const [userId, userData] of this.userLimits.entries()) {
            if (userData.blockUntil < now && userData.requests.length === 0) {
                this.userLimits.delete(userId);
            }
        }
    }
}

// Session Security Manager
class SessionSecurityManager {
    static async trackSession(user, req) {
        const geo = geoip.lookup(req.ip);
        const sessionData = {
            tokenId: crypto.randomUUID(),
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            country: geo?.country || 'UNKNOWN',
            city: geo?.city || 'UNKNOWN',
            createdAt: new Date()
        };

        // Add to user's active sessions
        user.activeSessions.push(sessionData);

        // Keep only last 10 sessions
        if (user.activeSessions.length > 10) {
            user.activeSessions = user.activeSessions.slice(-10);
        }

        await user.save();
        return sessionData.tokenId;
    }

    static async validateSession(userId, tokenId, currentIP) {
        const user = await AdminUser.findById(userId);
        if (!user) {
            return false;
        }

        const session = user.activeSessions.find(s => s.tokenId === tokenId);
        if (!session) {
            return false;
        }

        // Check if IP changed (potential session hijacking)
        if (session.ip !== currentIP) {
            console.log('🚨 Session IP mismatch:', {
                userId,
                originalIP: session.ip,
                currentIP,
                tokenId
            });
            return false;
        }

        return true;
    }

    static async revokeSession(userId, tokenId) {
        const user = await AdminUser.findById(userId);
        if (!user) {
            return;
        }

        user.activeSessions = user.activeSessions.filter(s => s.tokenId !== tokenId);
        await user.save();
    }
}

module.exports = {
    GeoSecurityManager,
    RequestSigner,
    TokenRateLimiter,
    SessionSecurityManager
};
