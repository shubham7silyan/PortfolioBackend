const express = require("express");
const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { SSLManager } = require("./config/ssl-setup");
const { HTTP2Server } = require("./config/http2-server");

// Import your existing app configuration
const mongoose = require("mongoose");
const cors = require("cors");
const { validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
require("dotenv").config();

// Import all your existing middleware
const {
    securityHeaders,
    contactLimiter,
    generalLimiter,
    adminLimiter,
    corsOptions,
    requestLogger,
    sanitizeInputs,
    securityErrorHandler
} = require("./middleware/security");

const {
    contactValidationRules,
    sanitizeInput,
    detectSuspiciousContent,
    detectRateLimitBypass
} = require("./utils/validation");

const {
    RefreshToken,
    AdminUser,
    TokenManager,
    authenticateToken,
    securityLogger,
    securityAlertSystem,
    ipBlockingMiddleware,
    logSecurityEvent
} = require("./middleware/logging");

const { PasswordManager } = require("./middleware/auth");

const {
    Role,
    RBACManager,
    UserRateLimit
} = require("./middleware/rbac");

const {
    GeoSecurityManager,
    RequestSigner,
    TokenRateLimiter,
    SessionSecurityManager
} = require("./middleware/geo-security");

const {
    ImmutableLogger,
    OffSiteLogger,
    EnhancedSecurityLogger
} = require("./middleware/immutable-logging");

const {
    cacheManager,
    performanceMonitor,
    asyncQueue,
    QueryOptimizer,
    compression
} = require("./middleware/performance");

class SecurePortfolioServer {
    constructor() {
        this.app = express();
        this.sslManager = new SSLManager();
        this.PORT = process.env.PORT || 5050;
        this.HTTPS_PORT = process.env.HTTPS_PORT || 443;
        this.HTTP_PORT = process.env.HTTP_PORT || 80;
        
        this.setupMiddleware();
        this.setupRoutes();
    }

    setupMiddleware() {
        // Initialize advanced security modules
        this.geoSecurity = new GeoSecurityManager();
        this.requestSigner = new RequestSigner();
        this.tokenRateLimiter = new TokenRateLimiter();
        this.enhancedLogger = new EnhancedSecurityLogger();

        // Apply Performance Middleware
        this.app.use(compression());
        this.app.use(performanceMonitor.trackRequest.bind(performanceMonitor));

        // Apply Security Middleware
        this.app.use(securityHeaders);
        this.app.use(ipBlockingMiddleware);
        this.app.use(generalLimiter);
        this.app.use("/contact", contactLimiter);
        this.app.use("/admin", adminLimiter);
        this.app.use("/admin", this.geoSecurity.geoRestrictMiddleware.bind(this.geoSecurity));
        this.app.use(requestLogger);
        this.app.use(express.json({ limit: "1mb" }));
        this.app.use(express.urlencoded({ extended: true, limit: "1mb" }));
        this.app.use(sanitizeInputs);
        this.app.use(cors(corsOptions));

        // Setup HTTP/2 server push
        HTTP2Server.setupServerPush(this.app);
    }

    setupRoutes() {
        // Import database security configuration
        const { DatabaseSecurity } = require("./config/database");
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

        const UserModel = mongoose.model("formdata", SchemaName);

        // All your existing routes with HTTPS security headers
        this.setupContactRoute(UserModel);
        this.setupAdminRoutes(UserModel);
        this.setupSystemRoutes();
        this.setupErrorHandlers();
    }

    setupContactRoute(UserModel) {
        this.app.post("/contact", contactValidationRules, async (req, res) => {
            try {
                // Add HTTPS security headers
                res.set({
                    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY',
                    'X-XSS-Protection': '1; mode=block'
                });

                const bypassCheck = detectRateLimitBypass(req);
                if (bypassCheck.suspicious) {
                    console.log("🚨 Rate limit bypass attempt detected:", {
                        ip: req.ip,
                        forwardedIPs: bypassCheck.forwardedIPs,
                        userAgent: req.get('User-Agent')
                    });
                }

                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    await logSecurityEvent('VALIDATION_FAILED', req, {
                        errors: errors.array(),
                        data: req.body
                    });
                    return res.status(400).json({
                        message: "Invalid input data",
                        success: false,
                        errors: errors.array()
                    });
                }

                const sanitizedData = sanitizeInput(req.body);
                const { FirstName, LastName, Email, Message } = sanitizedData;

                const emailCheck = validateEmail(Email);
                if (!emailCheck.valid) {
                    console.log("🚨 Invalid email detected:", {
                        ip: req.ip,
                        email: Email,
                        reason: emailCheck.reason
                    });
                    return res.status(400).json({
                        message: emailCheck.reason,
                        success: false
                    });
                }

                const suspiciousCheck = detectSuspiciousContent(sanitizedData);
                if (suspiciousCheck.suspicious) {
                    await logSecurityEvent('XSS_ATTEMPT', req, {
                        pattern: suspiciousCheck.pattern,
                        data: sanitizedData
                    });
                    return res.status(400).json({
                        message: "Invalid content detected",
                        success: false
                    });
                }

                if (!FirstName || !LastName || !Email || !Message) {
                    return res.status(400).json({ 
                        message: "All fields are required after sanitization",
                        success: false 
                    });
                }

                const newEntry = new UserModel(sanitizedData);
                await newEntry.save();
                console.log(`✅ Secure data saved - IP: ${req.ip}, Email: ${Email}`);

                res.status(200).json({ 
                    message: "Message sent successfully! I'll get back to you soon.",
                    success: true 
                });

            } catch (error) {
                console.error("❌ Security-enhanced error:", {
                    error: error.message,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date().toISOString()
                });
                
                if (error.name === 'ValidationError') {
                    res.status(400).json({ 
                        message: "Invalid data provided",
                        success: false 
                    });
                } else {
                    res.status(500).json({ 
                        message: "Something went wrong. Please try again later.",
                        success: false 
                    });
                }
            }
        });
    }

    setupAdminRoutes(UserModel) {
        // Admin login with HTTPS security
        this.app.post("/admin/login", async (req, res) => {
            try {
                res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
                
                const { username, password } = req.body;
                
                if (!username || !password) {
                    await logSecurityEvent('LOGIN_FAILED', req, { reason: 'Missing credentials' });
                    return res.status(400).json({
                        message: "Username and password required",
                        success: false
                    });
                }

                let adminUser = await AdminUser.findOne({ username });
                
                if (!adminUser) {
                    const defaultPassword = process.env.ADMIN_PASSWORD;
                    if (!defaultPassword) {
                        return res.status(500).json({
                            message: "Admin account not configured",
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

                if (adminUser.isLocked) {
                    await logSecurityEvent('LOGIN_FAILED', req, { 
                        reason: 'Account locked',
                        lockoutUntil: adminUser.lockoutUntil 
                    });
                    return res.status(423).json({
                        message: "Account temporarily locked due to failed attempts",
                        success: false,
                        lockoutUntil: adminUser.lockoutUntil
                    });
                }

                const isValidPassword = await PasswordManager.comparePassword(password, adminUser.passwordHash);
                
                if (!isValidPassword) {
                    await adminUser.incLoginAttempts();
                    await logSecurityEvent('LOGIN_FAILED', req, { 
                        reason: 'Invalid password',
                        attempts: adminUser.failedLoginAttempts + 1 
                    });
                    
                    return res.status(401).json({
                        message: "Invalid credentials",
                        success: false
                    });
                }

                await adminUser.resetLoginAttempts();

                const payload = { 
                    role: 'admin', 
                    userId: adminUser._id.toString(),
                    username: adminUser.username 
                };
                
                const { accessToken, refreshToken } = TokenManager.generateTokens(payload);
                await TokenManager.storeRefreshToken(refreshToken, adminUser._id.toString());

                securityLogger.info('Admin Login Successful', {
                    ip: req.ip,
                    username: adminUser.username,
                    timestamp: new Date().toISOString(),
                    secure: req.secure
                });

                const sessionId = await SessionSecurityManager.trackSession(adminUser, req);

                res.status(200).json({
                    message: "Login successful",
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
                    message: "Login failed",
                    success: false
                });
            }
        });

        // All other admin routes with HTTPS headers
        this.app.get("/admin/contacts", 
            authenticateToken, 
            RBACManager.requirePermission('contacts', 'read'),
            this.tokenRateLimiter.middleware(30, 15 * 60 * 1000),
            cacheManager.cacheMiddleware(60),
            async (req, res) => {
                res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
                
                try {
                    const page = parseInt(req.query.page) || 1;
                    const limit = parseInt(req.query.limit) || 20;
                    
                    const [contacts, totalCount] = await Promise.all([
                        QueryOptimizer.optimizeContactQueries().getContacts(page, limit),
                        QueryOptimizer.optimizeContactQueries().getContactCount()
                    ]);
                    
                    asyncQueue.queueLog({
                        level: 'info',
                        message: 'Admin accessed contacts via HTTPS',
                        metadata: {
                            userId: req.user.userId,
                            ip: req.ip,
                            count: contacts.length,
                            page,
                            limit,
                            secure: req.secure
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
                    console.error("❌ Error fetching contacts:", error);
                    res.status(500).json({ 
                        message: "Error fetching contacts",
                        success: false 
                    });
                }
            }
        );

        // Delete route with HMAC signing
        this.app.delete("/admin/contacts/:id", 
            this.requestSigner.verifySignature.bind(this.requestSigner),
            authenticateToken, 
            RBACManager.requirePermission('contacts', 'delete'),
            async (req, res) => {
                res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
                
                try {
                    const contact = await UserModel.findByIdAndDelete(req.params.id);
                    if (!contact) {
                        return res.status(404).json({ 
                            message: "Contact not found",
                            success: false 
                        });
                    }
                    
                    asyncQueue.queueLog({
                        level: 'warn',
                        message: 'Contact deleted via HTTPS',
                        metadata: {
                            userId: req.user.userId,
                            contactId: req.params.id,
                            ip: req.ip,
                            signatureVerified: req.signatureVerified,
                            secure: req.secure
                        }
                    });
                    
                    await cacheManager.del('GET:/admin/contacts:*');

                    res.status(200).json({ 
                        message: "Contact deleted successfully",
                        success: true 
                    });
                } catch (error) {
                    console.error("❌ Error deleting contact:", error);
                    res.status(500).json({ 
                        message: "Error deleting contact",
                        success: false 
                    });
                }
            }
        );
    }

    setupSystemRoutes() {
        // System status with SSL information
        this.app.get("/admin/system/status",
            authenticateToken,
            RBACManager.requirePermission('system', 'read'),
            cacheManager.cacheMiddleware(30),
            async (req, res) => {
                res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
                
                try {
                    const [integrity, activeUsers, sessionCount] = await Promise.all([
                        this.enhancedLogger.verifyLogIntegrity(),
                        AdminUser.countDocuments({ isActive: true }),
                        AdminUser.aggregate([
                            { $unwind: "$activeSessions" },
                            { $count: "total" }
                        ])
                    ]);
                    
                    const sslPaths = this.sslManager.getCertificatePaths();
                    
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
                            totalSessions: sessionCount[0]?.total || 0,
                            httpsEnabled: req.secure,
                            sslCertificate: sslPaths.exists
                        },
                        performance: performanceMonitor.getMetrics()
                    });
                } catch (error) {
                    res.status(500).json({
                        message: "System status unavailable",
                        success: false
                    });
                }
            }
        );

        // Health check with SSL status
        this.app.get("/health", (req, res) => {
            res.status(200).json({ 
                status: "OK", 
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                secure: req.secure,
                protocol: req.protocol
            });
        });
    }

    setupErrorHandlers() {
        this.app.use(securityErrorHandler);

        this.app.use('*', (req, res) => {
            console.log(`🚨 404 attempt - IP: ${req.ip}, Path: ${req.originalUrl}, Secure: ${req.secure}`);
            res.status(404).json({
                message: "Endpoint not found",
                success: false
            });
        });
    }

    // HTTP to HTTPS redirect middleware
    forceHTTPS(req, res, next) {
        if (!req.secure && req.get('x-forwarded-proto') !== 'https' && process.env.NODE_ENV === 'production') {
            return res.redirect(301, `https://${req.get('host')}${req.url}`);
        }
        next();
    }

    async initializeSSL() {
        console.log('🔐 Initializing SSL certificates...');
        
        const sslPaths = this.sslManager.getCertificatePaths();
        
        if (!sslPaths.exists) {
            console.log('📝 SSL certificates not found, generating...');
            
            if (process.env.NODE_ENV === 'production' && process.env.DOMAIN && process.env.ADMIN_EMAIL) {
                // Try Let's Encrypt for production
                const success = await this.sslManager.setupLetsEncrypt(process.env.DOMAIN, process.env.ADMIN_EMAIL);
                if (!success) {
                    console.log('⚠️ Let\'s Encrypt failed, using self-signed certificate');
                }
            } else {
                // Generate self-signed for development
                this.sslManager.generateSelfSignedCertificate();
            }
        } else {
            console.log('✅ SSL certificates found');
            this.sslManager.verifyCertificate();
        }
        
        return this.sslManager.getCertificatePaths();
    }

    async startServer() {
        try {
            // Initialize SSL certificates
            const sslPaths = await this.initializeSSL();
            
            if (sslPaths.exists) {
                // Create HTTPS server with HTTP/2 support
                const httpsOptions = {
                    key: fs.readFileSync(sslPaths.key),
                    cert: fs.readFileSync(sslPaths.cert)
                };

                // Try HTTP/2 first, fallback to HTTPS
                const http2Server = HTTP2Server.createSecureServer(this.app);
                
                if (http2Server) {
                    http2Server.listen(this.HTTPS_PORT, () => {
                        console.log(`🚀 HTTP/2 Secure server running on https://localhost:${this.HTTPS_PORT}`);
                        console.log(`🛡️ SSL/TLS encryption: ✅`);
                        console.log(`⚡ HTTP/2 with server push: ✅`);
                    });
                } else {
                    // Fallback to HTTPS
                    const httpsServer = https.createServer(httpsOptions, this.app);
                    httpsServer.listen(this.HTTPS_PORT, () => {
                        console.log(`🚀 HTTPS server running on https://localhost:${this.HTTPS_PORT}`);
                        console.log(`🛡️ SSL/TLS encryption: ✅`);
                    });
                }

                // HTTP server for redirects
                if (process.env.NODE_ENV === 'production') {
                    const httpApp = express();
                    httpApp.use(this.forceHTTPS);
                    httpApp.get('*', (req, res) => {
                        res.redirect(301, `https://${req.headers.host}${req.url}`);
                    });
                    
                    http.createServer(httpApp).listen(this.HTTP_PORT, () => {
                        console.log(`🔄 HTTP redirect server running on port ${this.HTTP_PORT}`);
                    });
                }
            } else {
                console.log('⚠️ SSL certificates not available, starting HTTP server only');
                this.app.listen(this.PORT, () => {
                    console.log(`🚀 HTTP server running on http://localhost:${this.PORT}`);
                    console.log('⚠️ For production, please configure SSL certificates');
                });
            }

            // Display security status
            console.log(`🛡️ Security features enabled:`);
            console.log(`   - Rate limiting: ✅`);
            console.log(`   - Input validation: ✅`);
            console.log(`   - XSS protection: ✅`);
            console.log(`   - CORS security: ✅`);
            console.log(`   - JWT authentication: ✅`);
            console.log(`   - Request logging: ✅`);
            console.log(`   - RBAC permissions: ✅`);
            console.log(`   - Geo-IP restrictions: ✅`);
            console.log(`   - HTTPS/SSL: ${sslPaths.exists ? '✅' : '⚠️'}`);
            
        } catch (error) {
            console.error('❌ Failed to start server:', error);
            process.exit(1);
        }
    }
}

// Export for use
module.exports = { SecurePortfolioServer };

// Start server if this file is run directly
if (require.main === module) {
    const server = new SecurePortfolioServer();
    server.startServer();
}
