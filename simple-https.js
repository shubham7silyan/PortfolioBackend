const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { validateEmail } = require('./utils/validation');

// Import your existing app from index.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { validationResult } = require('express-validator');
require('dotenv').config();

// Create Express app with all existing middleware
const app = express();

// Import all existing middleware
const {
    securityHeaders,
    contactLimiter,
    generalLimiter,
    adminLimiter,
    corsOptions,
    requestLogger,
    sanitizeInputs,
    securityErrorHandler
} = require('./middleware/security');

const {
    contactValidationRules,
    sanitizeInput,
    detectSuspiciousContent,
    detectRateLimitBypass
} = require('./utils/validation');

const {
    RefreshToken,
    AdminUser,
    TokenManager,
    authenticateToken,
    securityLogger,
    ipBlockingMiddleware,
    logSecurityEvent
} = require('./middleware/logging');

const { PasswordManager } = require('./middleware/auth');

const {
    Role,
    RBACManager,
    UserRateLimit
} = require('./middleware/rbac');

const {
    GeoSecurityManager,
    RequestSigner,
    TokenRateLimiter,
    SessionSecurityManager,
    EnhancedSecurityLogger
} = require('./middleware/geo-security');

const {
    cacheManager,
    performanceMonitor,
    asyncQueue,
    QueryOptimizer,
    compression
} = require('./middleware/performance');

const { SEOOptimizer } = require('./seo-optimization');

// Initialize security modules
const geoSecurity = new GeoSecurityManager();
const requestSigner = new RequestSigner();
const tokenRateLimiter = new TokenRateLimiter();
const enhancedLogger = new EnhancedSecurityLogger();

// Apply all middleware
app.use(compression());
app.use(performanceMonitor.trackRequest.bind(performanceMonitor));
app.use(securityHeaders);
app.use(ipBlockingMiddleware);
app.use(generalLimiter);
app.use('/contact', contactLimiter);
app.use('/admin', adminLimiter);
app.use('/admin', geoSecurity.geoRestrictMiddleware.bind(geoSecurity));
app.use(requestLogger);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(sanitizeInputs);
app.use(cors(corsOptions));

// Initialize SEO optimization
const seoOptimizer = new SEOOptimizer(app);

// Enhanced HTTPS security middleware
app.use((req, res, next) => {
    if (req.secure) {
        res.set({
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        });
    }
    next();
});

// Database connection
const { DatabaseSecurity } = require('./config/database');
DatabaseSecurity.connectSecurely();
RBACManager.initializeRoles();

// Schema
const SchemaName = new mongoose.Schema({
    FirstName: { type: String, required: true },
    LastName: { type: String, required: true },
    Email: { type: String, required: true },
    Message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const UserModel = mongoose.model('formdata', SchemaName);

// All existing routes with HTTPS enhancements
app.post('/contact', contactValidationRules, async (req, res) => {
    try {
        const bypassCheck = detectRateLimitBypass(req);
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            await logSecurityEvent('VALIDATION_FAILED', req, { errors: errors.array() });
            return res.status(400).json({
                message: 'Invalid input data',
                success: false,
                errors: errors.array()
            });
        }

        const sanitizedData = sanitizeInput(req.body);
        const { FirstName, LastName, Email, Message } = sanitizedData;

        const emailCheck = validateEmail(Email);
        if (!emailCheck.valid) {
            return res.status(400).json({
                message: emailCheck.reason,
                success: false
            });
        }

        const suspiciousCheck = detectSuspiciousContent(sanitizedData);
        if (suspiciousCheck.suspicious) {
            await logSecurityEvent('XSS_ATTEMPT', req, { pattern: suspiciousCheck.pattern });
            return res.status(400).json({
                message: 'Invalid content detected',
                success: false
            });
        }

        const newEntry = new UserModel(sanitizedData);
        await newEntry.save();

        console.log(`✅ Secure HTTPS data saved - IP: ${req.ip}, Email: ${Email}, Protocol: ${req.protocol}`);

        res.status(200).json({
            message: 'Message sent securely! I\'ll get back to you soon.',
            success: true,
            secure: req.secure
        });

    } catch (error) {
        console.error('❌ HTTPS error:', error.message);
        res.status(500).json({
            message: 'Something went wrong. Please try again later.',
            success: false
        });
    }
});

// Admin routes with HTTPS security
app.get('/admin/contacts',
    authenticateToken,
    RBACManager.requirePermission('contacts', 'read'),
    tokenRateLimiter.middleware(30, 15 * 60 * 1000),
    cacheManager.cacheMiddleware(60),
    async (req, res) => {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 20;

            const [contacts, totalCount] = await Promise.all([
                QueryOptimizer.optimizeContactQueries().getContacts(page, limit),
                QueryOptimizer.optimizeContactQueries().getContactCount()
            ]);

            res.status(200).json({
                success: true,
                count: contacts.length,
                totalCount,
                page,
                totalPages: Math.ceil(totalCount / limit),
                data: contacts,
                secure: req.secure
            });
        } catch (error) {
            res.status(500).json({
                message: 'Error fetching contacts',
                success: false
            });
        }
    }
);

// Health check with SSL status
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        secure: req.secure,
        protocol: req.protocol,
        ssl: req.secure ? '✅ HTTPS Enabled' : '⚠️ HTTP Only'
    });
});

// SSL certificate info endpoint
app.get('/ssl-info', (req, res) => {
    const sslDir = path.join(__dirname, 'config', 'ssl');
    const certExists = fs.existsSync(path.join(sslDir, 'certificate.pem'));
    const keyExists = fs.existsSync(path.join(sslDir, 'private-key.pem'));

    res.status(200).json({
        ssl: {
            certificateExists: certExists,
            privateKeyExists: keyExists,
            httpsEnabled: req.secure,
            protocol: req.protocol,
            host: req.get('host')
        }
    });
});

app.use(securityErrorHandler);

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        message: 'Endpoint not found',
        success: false,
        secure: req.secure
    });
});

// Server startup
const HTTPS_PORT = process.env.HTTPS_PORT || 443;
const HTTP_PORT = process.env.HTTP_PORT || 5050;

try {
    const sslDir = path.join(__dirname, 'config', 'ssl');
    const certPath = path.join(sslDir, 'certificate.pem');
    const keyPath = path.join(sslDir, 'private-key.pem');

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        // HTTPS Server
        const httpsOptions = {
            key: fs.readFileSync(keyPath),
            cert: fs.readFileSync(certPath)
        };

        const httpsServer = https.createServer(httpsOptions, app);

        httpsServer.listen(HTTPS_PORT, () => {
            console.log('🔐 SSL Certificate Setup Complete!');
            console.log('=====================================');
            console.log(`🚀 HTTPS Server: https://localhost:${HTTPS_PORT}`);
            console.log('🛡️ SSL/TLS Encryption: ✅ Enabled');
            console.log('📈 SEO Ranking Factor: ✅ HTTPS Active');
            console.log('🔒 Security Headers: ✅ HSTS, XSS Protection');
            console.log('=====================================');
            console.log('🌐 Test endpoints:');
            console.log(`   Health: https://localhost:${HTTPS_PORT}/health`);
            console.log(`   SSL Info: https://localhost:${HTTPS_PORT}/ssl-info`);
            console.log(`   Contact: https://localhost:${HTTPS_PORT}/contact`);
            console.log('=====================================');
        });

        // HTTP redirect server for production
        if (process.env.NODE_ENV === 'production') {
            const redirectApp = express();
            redirectApp.get('*', (req, res) => {
                res.redirect(301, `https://${req.headers.host}${req.url}`);
            });

            http.createServer(redirectApp).listen(HTTP_PORT, () => {
                console.log(`🔄 HTTP → HTTPS Redirect: Port ${HTTP_PORT}`);
            });
        }

    } else {
        console.log('⚠️ SSL certificates not found, starting HTTP server');
        app.listen(HTTP_PORT, () => {
            console.log(`🚀 HTTP Server: http://localhost:${HTTP_PORT}`);
            console.log('🔧 To enable HTTPS, run: npm run ssl:quick');
        });
    }

} catch (error) {
    console.error('❌ Server startup error:', error.message);

    // Fallback to HTTP
    app.listen(HTTP_PORT, () => {
        console.log(`🚀 Fallback HTTP Server: http://localhost:${HTTP_PORT}`);
        console.log('⚠️ HTTPS unavailable, check SSL configuration');
    });
}
