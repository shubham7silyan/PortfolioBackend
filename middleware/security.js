const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const morgan = require('morgan');
const cors = require('cors');

// Security Headers
const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", 'data:', 'https:'],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
});

// Rate Limiting Configurations
const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 contact form submissions per window
    message: {
        error: 'Too many contact form submissions. Please try again in 15 minutes.',
        success: false,
        retryAfter: 15 * 60 // seconds
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for health checks
        return req.path === '/health';
    }
});

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: {
        error: 'Too many requests. Please try again later.',
        success: false,
        retryAfter: 15 * 60
    },
    standardHeaders: true,
    legacyHeaders: false
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 admin requests per window
    message: {
        error: 'Too many admin requests. Please try again later.',
        success: false
    }
});

// CORS Configuration
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            process.env.FRONTEND_URL || 'http://localhost:3000',
            'http://localhost:3000',
            'http://127.0.0.1:3000'
        ];
        
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

// Request Logging
const requestLogger = morgan('combined', {
    skip: (req) => {
        // Skip logging for health checks in production
        return process.env.NODE_ENV === 'production' && req.path === '/health';
    }
});

// Input Sanitization
const sanitizeInputs = (req, res, next) => {
    // Remove any MongoDB operators from request body
    mongoSanitize()(req, res, next);
};

// Security Error Handler
const securityErrorHandler = (err, req, res, next) => {
    console.error('🚨 Security Error:', {
        error: err.message,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        timestamp: new Date().toISOString()
    });

    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({
            error: 'Access denied',
            success: false
        });
    }

    res.status(500).json({
        error: 'Security error occurred',
        success: false
    });
};

module.exports = {
    securityHeaders,
    contactLimiter,
    generalLimiter,
    adminLimiter,
    corsOptions,
    requestLogger,
    sanitizeInputs,
    securityErrorHandler
};
