const rateLimit = require('express-rate-limit');
const { cacheManager, asyncQueue } = require('./performance');

// Optimized Security Middleware - Apply rate limiting only to critical routes
class OptimizedSecurity {
    static createSmartRateLimit(windowMs = 15 * 60 * 1000, max = 100, message = "Too many requests") {
        return rateLimit({
            windowMs,
            max,
            message: { message, success: false },
            standardHeaders: true,
            legacyHeaders: false,
            // Skip successful requests from counting against limit
            skip: (req, res) => res.statusCode < 400,
            // Use Redis store if available, memory otherwise
            store: cacheManager.isConnected ? new rateLimit.RedisStore({
                client: cacheManager.client,
                prefix: 'rl:'
            }) : new rateLimit.MemoryStore()
        });
    }

    // Critical route rate limiting (login, contact)
    static criticalLimiter = this.createSmartRateLimit(15 * 60 * 1000, 5, "Too many attempts, please try again later");
    
    // Contact form specific limiting
    static contactLimiter = this.createSmartRateLimit(60 * 1000, 2, "Please wait before submitting another message");
    
    // Admin route limiting (more permissive for authenticated users)
    static adminLimiter = this.createSmartRateLimit(15 * 60 * 1000, 100, "Admin rate limit exceeded");

    // Async logging middleware - don't block requests
    static asyncSecurityLogger(eventType) {
        return (req, res, next) => {
            // Queue security logging instead of blocking
            asyncQueue.add(async () => {
                const { logSecurityEvent } = require('./logging');
                await logSecurityEvent(eventType, req, {
                    path: req.path,
                    method: req.method,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date().toISOString()
                });
            });
            next();
        };
    }

    // Optimized input validation - fail fast
    static fastValidation(req, res, next) {
        const { body } = req;
        
        // Quick checks first
        if (!body || typeof body !== 'object') {
            return res.status(400).json({ message: "Invalid request body", success: false });
        }

        // Check for obviously malicious patterns
        const suspiciousPatterns = [
            /<script/i, /javascript:/i, /vbscript:/i, /onload=/i, /onerror=/i
        ];

        const bodyStr = JSON.stringify(body);
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(bodyStr)) {
                return res.status(400).json({ message: "Invalid content detected", success: false });
            }
        }

        next();
    }

    // Performance-optimized CORS
    static optimizedCORS = {
        origin: (origin, callback) => {
            // Allow requests with no origin (mobile apps, Postman, etc.)
            if (!origin) return callback(null, true);
            
            const allowedOrigins = [
                process.env.FRONTEND_URL,
                'http://localhost:3000',
                'https://localhost:3000'
            ].filter(Boolean);

            if (allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        optionsSuccessStatus: 200,
        maxAge: 86400 // Cache preflight for 24 hours
    };
}

module.exports = {
    OptimizedSecurity
};
