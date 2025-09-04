const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Import security middleware and validation utilities
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
    validateEmail,
    detectRateLimitBypass
} = require('./utils/validation');

const {
    RefreshToken,
    AdminUser,
    TokenManager,
    securityLogger,
    securityAlertSystem,
    ipBlockingMiddleware,
    logSecurityEvent
} = require('./middleware/logging');

const { PasswordManager } = require('./middleware/auth');

// Import advanced security modules
const {
    Role,
    RBACManager,
    UserRateLimit
} = require('./middleware/rbac');

const {
    GeoSecurityManager,
    RequestSigner,
    TokenRateLimiter,
    SessionSecurityManager
} = require('./middleware/geo-security');

const {
    ImmutableLogger,
    OffSiteLogger,
    EnhancedSecurityLogger
} = require('./middleware/immutable-logging');

// Import performance modules
const {
    cacheManager,
    performanceMonitor,
    asyncQueue,
    QueryOptimizer,
    compression
} = require('./middleware/performance');

const app = express();
const PORT = process.env.PORT || 5050;

// Initialize advanced security modules
const geoSecurity = new GeoSecurityManager();
const requestSigner = new RequestSigner();
const tokenRateLimiter = new TokenRateLimiter();
const enhancedLogger = new EnhancedSecurityLogger();

// Apply Performance Middleware
app.use(compression()); // Enable gzip/brotli compression
app.use(performanceMonitor.trackRequest.bind(performanceMonitor)); // Performance tracking

// Apply Security Middleware
app.use(securityHeaders);
app.use(ipBlockingMiddleware); // IP blocking for suspicious activity
app.use(generalLimiter);
app.use('/contact', contactLimiter);
app.use('/admin', adminLimiter);
app.use('/admin', geoSecurity.geoRestrictMiddleware.bind(geoSecurity)); // Geo-IP restrictions for admin
app.use(requestLogger);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(sanitizeInputs);
app.use(cors(corsOptions));

// Import database security configuration
const { DatabaseSecurity } = require('./config/database');

// Connect to MongoDB with security and initialize components after connection
async function initializeServer() {
    try {
        await DatabaseSecurity.connectSecurely();

        // Only initialize database-dependent components if not in bypass mode
        if (process.env.DB_BYPASS !== 'true') {
            // Initialize RBAC roles after MongoDB connection
            await RBACManager.initializeRoles();
        } else {
            console.log('⚠️ RBAC initialization skipped - database bypass mode');
        }

        console.log('✅ Server initialization completed');

        // Schema
        const SchemaName = new mongoose.Schema({
            FirstName: { type: String, required: true },
            LastName: { type: String, required: true },
            Email: { type: String, required: true },
            Message: { type: String, required: true },
            createdAt: { type: Date, default: Date.now }
        }, { versionKey: false });

        const UserModel = mongoose.model('formdata', SchemaName);

        // Enhanced POST Route with Advanced Security Features
        app.post('/contact', contactValidationRules, async (req, res) => {
            try {
                // Check for rate limit bypass attempts
                const bypassCheck = detectRateLimitBypass(req);
                if (bypassCheck.suspicious) {
                    console.log('🚨 Rate limit bypass attempt detected:', {
                        ip: req.ip,
                        forwardedIPs: bypassCheck.forwardedIPs,
                        userAgent: req.get('User-Agent')
                    });
                }

                // Check validation errors
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    await logSecurityEvent('VALIDATION_FAILED', req, {
                        errors: errors.array(),
                        data: req.body
                    });
                    return res.status(400).json({
                        message: 'Invalid input data',
                        success: false,
                        errors: errors.array()
                    });
                }

                // Sanitize input data
                const sanitizedData = sanitizeInput(req.body);
                const { FirstName, LastName, Email, Message } = sanitizedData;

                // Advanced email validation
                const emailCheck = validateEmail(Email);
                if (!emailCheck.valid) {
                    console.log('🚨 Invalid email detected:', {
                        ip: req.ip,
                        email: Email,
                        reason: emailCheck.reason
                    });
                    return res.status(400).json({
                        message: emailCheck.reason,
                        success: false
                    });
                }

                // Check for suspicious content patterns
                const suspiciousCheck = detectSuspiciousContent(sanitizedData);
                if (suspiciousCheck.suspicious) {
                    await logSecurityEvent('XSS_ATTEMPT', req, {
                        pattern: suspiciousCheck.pattern,
                        data: sanitizedData
                    });
                    return res.status(400).json({
                        message: 'Invalid content detected',
                        success: false
                    });
                }

                // Final validation check
                if (!FirstName || !LastName || !Email || !Message) {
                    return res.status(400).json({
                        message: 'All fields are required after sanitization',
                        success: false
                    });
                }

                // Save to database with sanitized data
                const newEntry = new UserModel(sanitizedData);
                await newEntry.save();
                console.log(`✅ Secure data saved - IP: ${req.ip}, Email: ${Email}`);

                res.status(200).json({
                    message: 'Message sent successfully! I\'ll get back to you soon.',
                    success: true
                });

            } catch (error) {
                console.error('❌ Security-enhanced error:', {
                    error: error.message,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date().toISOString()
                });

                // Don't expose internal errors to client
                if (error.name === 'ValidationError') {
                    res.status(400).json({
                        message: 'Invalid data provided',
                        success: false
                    });
                } else {
                    res.status(500).json({
                        message: 'Something went wrong. Please try again later.',
                        success: false
                    });
                }
            }
        });

        // JWT Authentication Middleware
        const authenticateToken = (req, res, next) => {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];

            if (!token) {
                return res.status(401).json({
                    message: 'Access token required',
                    success: false
                });
            }

            jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
                if (err) {
                    return res.status(403).json({
                        message: 'Invalid or expired token',
                        success: false
                    });
                }
                req.user = user;
                next();
            });
        };

        // Enhanced Admin Login with Account Lockout & Refresh Tokens
        app.post('/admin/login', async (req, res) => {
            try {
                const { username, password } = req.body;

                if (!username || !password) {
                    await logSecurityEvent('LOGIN_FAILED', req, { reason: 'Missing credentials' });
                    return res.status(400).json({
                        message: 'Username and password required',
                        success: false
                    });
                }

                // Find admin user
                let adminUser = await AdminUser.findOne({ username });

                // Create default admin if doesn't exist
                if (!adminUser) {
                    const defaultPassword = process.env.ADMIN_PASSWORD;
                    if (!defaultPassword) {
                        return res.status(500).json({
                            message: 'Admin account not configured',
                            success: false
                        });
                    }

                    const hashedPassword = await PasswordManager.hashPassword(defaultPassword);
                    adminUser = new AdminUser({
                        username: 'admin',
                        passwordHash: hashedPassword
                    });
                    await adminUser.save();
                }

                // Check if account is locked
                if (adminUser.isLocked) {
                    await logSecurityEvent('LOGIN_FAILED', req, {
                        reason: 'Account locked',
                        lockoutUntil: adminUser.lockoutUntil
                    });
                    return res.status(423).json({
                        message: 'Account temporarily locked due to failed attempts',
                        success: false,
                        lockoutUntil: adminUser.lockoutUntil
                    });
                }

                // Verify password
                const isValidPassword = await PasswordManager.comparePassword(password, adminUser.passwordHash);

                if (!isValidPassword) {
                    await adminUser.incLoginAttempts();
                    await logSecurityEvent('LOGIN_FAILED', req, {
                        reason: 'Invalid password',
                        attempts: adminUser.failedLoginAttempts + 1
                    });

                    return res.status(401).json({
                        message: 'Invalid credentials',
                        success: false
                    });
                }

                // Reset failed attempts on successful login
                await adminUser.resetLoginAttempts();

                // Generate tokens
                const payload = {
                    role: 'admin',
                    userId: adminUser._id.toString(),
                    username: adminUser.username
                };

                const { accessToken, refreshToken } = TokenManager.generateTokens(payload);

                // Store refresh token
                await TokenManager.storeRefreshToken(refreshToken, adminUser._id.toString());

                securityLogger.info('Admin Login Successful', {
                    ip: req.ip,
                    username: adminUser.username,
                    timestamp: new Date().toISOString()
                });

                // Track session for security
                const sessionId = await SessionSecurityManager.trackSession(adminUser, req);

                res.status(200).json({
                    message: 'Login successful',
                    success: true,
                    accessToken,
                    refreshToken,
                    expiresIn: '15m',
                    sessionId
                });

            } catch (error) {
                securityLogger.error('Admin Login Error', {
                    error: error.message,
                    ip: req.ip,
                    timestamp: new Date().toISOString()
                });

                res.status(500).json({
                    message: 'Login failed',
                    success: false
                });
            }
        });

        // Refresh Token Endpoint
        app.post('/admin/refresh', async (req, res) => {
            try {
                const { refreshToken } = req.body;

                if (!refreshToken) {
                    return res.status(401).json({
                        message: 'Refresh token required',
                        success: false
                    });
                }

                // Validate refresh token
                const tokenDoc = await TokenManager.validateRefreshToken(refreshToken);
                if (!tokenDoc) {
                    await logSecurityEvent('TOKEN_REFRESH_FAILED', req, { reason: 'Invalid refresh token' });
                    return res.status(403).json({
                        message: 'Invalid or expired refresh token',
                        success: false
                    });
                }

                // Generate new tokens
                const payload = {
                    role: 'admin',
                    userId: tokenDoc.userId,
                    username: 'admin'
                };

                const { accessToken, refreshToken: newRefreshToken } = TokenManager.generateTokens(payload);

                // Revoke old refresh token and store new one
                await TokenManager.revokeRefreshToken(refreshToken);
                await TokenManager.storeRefreshToken(newRefreshToken, tokenDoc.userId);

                res.status(200).json({
                    message: 'Token refreshed successfully',
                    success: true,
                    accessToken,
                    refreshToken: newRefreshToken,
                    expiresIn: '15m'
                });

            } catch (error) {
                securityLogger.error('Token Refresh Error', {
                    error: error.message,
                    ip: req.ip,
                    timestamp: new Date().toISOString()
                });

                res.status(500).json({
                    message: 'Token refresh failed',
                    success: false
                });
            }
        });

        // Admin Logout (Revoke Tokens)
        app.post('/admin/logout', authenticateToken, async (req, res) => {
            try {
                const { refreshToken } = req.body;

                if (refreshToken) {
                    await TokenManager.revokeRefreshToken(refreshToken);
                }

                // Optionally revoke all user tokens
                if (req.body.logoutAll) {
                    await TokenManager.revokeAllUserTokens(req.user.userId);
                }

                res.status(200).json({
                    message: 'Logged out successfully',
                    success: true
                });

            } catch (error) {
                res.status(500).json({
                    message: 'Logout failed',
                    success: false
                });
            }
        });

        // Optimized Protected API Routes with Caching and RBAC
        app.get('/admin/contacts',
            authenticateToken,
            RBACManager.requirePermission('contacts', 'read'),
            tokenRateLimiter.middleware(30, 15 * 60 * 1000),
            cacheManager.cacheMiddleware(60), // Cache for 60 seconds
            async (req, res) => {
                try {
                    const page = parseInt(req.query.page) || 1;
                    const limit = parseInt(req.query.limit) || 20;

                    // Use optimized query with parallel execution
                    const [contacts, totalCount] = await Promise.all([
                        QueryOptimizer.optimizeContactQueries().getContacts(page, limit),
                        QueryOptimizer.optimizeContactQueries().getContactCount()
                    ]);

                    // Queue logging instead of blocking request
                    asyncQueue.queueLog({
                        level: 'info',
                        message: 'Admin accessed contacts',
                        metadata: {
                            userId: req.user.userId,
                            ip: req.ip,
                            count: contacts.length,
                            page,
                            limit
                        }
                    });

                    res.status(200).json({
                        success: true,
                        count: contacts.length,
                        totalCount,
                        page,
                        totalPages: Math.ceil(totalCount / limit),
                        data: contacts
                    });
                } catch (error) {
                    console.error('❌ Error fetching contacts:', error);
                    res.status(500).json({
                        message: 'Error fetching contacts',
                        success: false
                    });
                }
            }
        );

        // Optimized single contact fetch with caching
        app.get('/admin/contacts/:id',
            authenticateToken,
            RBACManager.requirePermission('contacts', 'read'),
            cacheManager.cacheMiddleware(300), // Cache for 5 minutes
            async (req, res) => {
                try {
                    const contact = await UserModel.findById(req.params.id).lean();
                    if (!contact) {
                        return res.status(404).json({
                            message: 'Contact not found',
                            success: false
                        });
                    }
                    res.status(200).json({
                        success: true,
                        data: contact
                    });
                } catch (error) {
                    console.error('❌ Error fetching contact:', error);
                    res.status(500).json({
                        message: 'Error fetching contact',
                        success: false
                    });
                }
            }
        );

        // Fast contact search endpoint
        app.get('/admin/contacts/search/:query',
            authenticateToken,
            RBACManager.requirePermission('contacts', 'read'),
            cacheManager.cacheMiddleware(120), // Cache for 2 minutes
            async (req, res) => {
                try {
                    const results = await QueryOptimizer.optimizeContactQueries().searchContacts(req.params.query);
                    res.status(200).json({
                        success: true,
                        count: results.length,
                        data: results
                    });
                } catch (error) {
                    console.error('❌ Error searching contacts:', error);
                    res.status(500).json({
                        message: 'Search failed',
                        success: false
                    });
                }
            }
        );

        // Critical Admin Routes with HMAC Signing
        app.delete('/admin/contacts/:id',
            requestSigner.verifySignature.bind(requestSigner),
            authenticateToken,
            RBACManager.requirePermission('contacts', 'delete'),
            async (req, res) => {
                try {
                    const contact = await UserModel.findByIdAndDelete(req.params.id);
                    if (!contact) {
                        return res.status(404).json({
                            message: 'Contact not found',
                            success: false
                        });
                    }

                    // Queue critical action logging and cache invalidation
                    asyncQueue.queueLog({
                        level: 'warn',
                        message: 'Contact deleted',
                        metadata: {
                            userId: req.user.userId,
                            contactId: req.params.id,
                            ip: req.ip,
                            signatureVerified: req.signatureVerified
                        }
                    });

                    // Invalidate contacts cache
                    await cacheManager.del('GET:/admin/contacts:*');

                    res.status(200).json({
                        message: 'Contact deleted successfully',
                        success: true
                    });
                } catch (error) {
                    console.error('❌ Error deleting contact:', error);
                    res.status(500).json({
                        message: 'Error deleting contact',
                        success: false
                    });
                }
            }
        );

        // System Status with RBAC and Performance Metrics
        app.get('/admin/system/status',
            authenticateToken,
            RBACManager.requirePermission('system', 'read'),
            cacheManager.cacheMiddleware(30), // Cache for 30 seconds
            async (req, res) => {
                try {
                    // Run checks in parallel for better performance
                    const [integrity, activeUsers, sessionCount] = await Promise.all([
                        enhancedLogger.verifyLogIntegrity(),
                        AdminUser.countDocuments({ isActive: true }),
                        AdminUser.aggregate([
                            { $unwind: '$activeSessions' },
                            { $count: 'total' }
                        ])
                    ]);

                    res.status(200).json({
                        success: true,
                        system: {
                            uptime: process.uptime(),
                            memory: process.memoryUsage(),
                            nodeVersion: process.version,
                            environment: process.env.NODE_ENV,
                            pid: process.pid
                        },
                        security: {
                            logIntegrity: integrity,
                            activeUsers,
                            totalSessions: sessionCount[0]?.total || 0
                        },
                        performance: performanceMonitor.getMetrics()
                    });
                } catch (error) {
                    res.status(500).json({
                        message: 'System status unavailable',
                        success: false
                    });
                }
            }
        );

        // Health check endpoint
        app.get('/health', (req, res) => {
            res.status(200).json({
                status: 'OK',
                timestamp: new Date().toISOString(),
                uptime: process.uptime()
            });
        });

        // Security Error Handler
        app.use(securityErrorHandler);

        // 404 Handler
        app.use('*', (req, res) => {
            console.log(`🚨 404 attempt - IP: ${req.ip}, Path: ${req.originalUrl}`);
            res.status(404).json({
                message: 'Endpoint not found',
                success: false
            });
        });

        // Start server with security logging
        app.listen(PORT, () => {
            console.log(`🚀 Secure server running on http://localhost:${PORT}`);
            console.log('🛡️ Security features enabled:');
            console.log('   - Rate limiting: ✅');
            console.log('   - Input validation: ✅');
            console.log('   - XSS protection: ✅');
            console.log('   - CORS security: ✅');
            console.log('   - JWT authentication: ✅');
            console.log('   - Request logging: ✅');
            console.log(`📊 Health check: http://localhost:${PORT}/health`);
            console.log(`📧 Contact API: http://localhost:${PORT}/contact`);
            console.log(`🔐 Admin API: http://localhost:${PORT}/admin/*`);
        });
    } catch (error) {
        console.error('❌ Server initialization failed:', error);
        process.exit(1);
    }
}

// Initialize server
initializeServer();
