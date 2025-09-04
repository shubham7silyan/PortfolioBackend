const winston = require('winston');
const { MongoDB } = require('winston-mongodb');
const { RefreshToken, AdminUser, TokenManager, authenticateToken } = require('./auth');

// Security Alert System
class SecurityAlertSystem {
    constructor() {
        this.suspiciousIPs = new Map();
        this.blockedIPs = new Set();
        this.alertThreshold = 5; // Alert after 5 suspicious activities
        this.blockThreshold = 10; // Block after 10 suspicious activities
        this.timeWindow = 15 * 60 * 1000; // 15 minutes
    }
    
    async recordSuspiciousActivity(ip, activity, details = {}) {
        const now = Date.now();
        const ipData = this.suspiciousIPs.get(ip) || { count: 0, lastAttempt: 0, blocked: false };
        
        // Reset count if outside time window
        if (now - ipData.lastAttempt > this.timeWindow) {
            ipData.count = 0;
            ipData.blocked = false;
        }
        
        ipData.count++;
        ipData.lastAttempt = now;
        
        // Log the activity
        securityLogger.warn('Suspicious Activity Detected', {
            ip,
            activity,
            count: ipData.count,
            details,
            timestamp: new Date().toISOString()
        });
        
        // Block IP if block threshold reached
        if (ipData.count >= this.blockThreshold) {
            ipData.blocked = true;
            this.blockedIPs.add(ip);
        }
        
        this.suspiciousIPs.set(ip, ipData);
        return ipData.blocked;
    }
    
    isBlocked(ip) {
        const ipData = this.suspiciousIPs.get(ip);
        if (!ipData) {
            return false;
        }
        
        const now = Date.now();
        if (now - ipData.lastAttempt > this.timeWindow) {
            ipData.blocked = false;
            this.suspiciousIPs.set(ip, ipData);
            this.blockedIPs.delete(ip);
            return false;
        }
        
        return ipData.blocked;
    }
}

// Winston Logger Configuration
const securityLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'portfolio-security' },
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/security.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// Add MongoDB transport if connection available
if (process.env.MONGODB_URI && process.env.DB_BYPASS !== 'true') {
    securityLogger.add(new MongoDB({
        db: process.env.MONGODB_URI,
        collection: 'security_logs',
        level: 'info'
    }));
}

// Security Alert System Instance
const securityAlertSystem = new SecurityAlertSystem();

// IP Blocking Middleware
const ipBlockingMiddleware = (req, res, next) => {
    const clientIP = req.ip;
    
    if (securityAlertSystem.isBlocked(clientIP)) {
        securityLogger.warn('Blocked IP Access Attempt', {
            ip: clientIP,
            path: req.path,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString()
        });
        
        return res.status(403).json({
            message: 'Access denied',
            success: false
        });
    }
    
    next();
};

// Security Event Logging
const logSecurityEvent = async (eventType, req, additionalData = {}) => {
    const eventData = {
        type: eventType,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString(),
        ...additionalData
    };
    
    securityLogger.warn('Security Event', eventData);
    
    // Record suspicious activity for certain event types
    const suspiciousEvents = ['XSS_ATTEMPT', 'SQL_INJECTION', 'VALIDATION_FAILED', 'LOGIN_FAILED'];
    if (suspiciousEvents.includes(eventType)) {
        await securityAlertSystem.recordSuspiciousActivity(req.ip, eventType, eventData);
    }
};

module.exports = {
    RefreshToken,
    AdminUser,
    TokenManager,
    authenticateToken,
    securityLogger,
    securityAlertSystem,
    ipBlockingMiddleware,
    logSecurityEvent
};
