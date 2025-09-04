const mongoose = require('mongoose');

// Enhanced Database Configuration with Security and Performance
class DatabaseSecurity {
    static async connectSecurely() {
        try {
            // Check if database bypass is enabled for development
            if (process.env.DB_BYPASS === 'true') {
                console.log('⚠️ Database bypass enabled - running without MongoDB');
                console.log('✅ Database bypass mode active');
                return;
            }

            const options = {
                authSource: 'admin',
                tls: process.env.NODE_ENV === 'production',
                tlsAllowInvalidCertificates: process.env.NODE_ENV !== 'production',

                // Performance optimizations
                maxPoolSize: 20, // Increased pool size
                minPoolSize: 5,
                maxIdleTimeMS: 30000,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 45000,
                bufferCommands: true,

                // Connection monitoring
                monitorCommands: true,
                compressors: ['zlib'], // Enable compression
                zlibCompressionLevel: 6
            };

            // Add authentication if credentials provided
            if (process.env.MONGODB_USERNAME && process.env.MONGODB_PASSWORD) {
                options.auth = {
                    username: process.env.MONGODB_USERNAME,
                    password: process.env.MONGODB_PASSWORD
                };
            }

            await mongoose.connect(process.env.MONGODB_URI, options);
            console.log('✅ MongoDB connected securely with performance optimizations');

            // Create security and performance indexes
            await this.createOptimizedIndexes();

        } catch (error) {
            console.error('❌ MongoDB connection failed:', error.message);
            console.log('💡 To bypass database for testing, set DB_BYPASS=true in .env');
            console.log('💡 Or whitelist your IP in MongoDB Atlas Network Access');
            process.exit(1);
        }
    }

    static async createOptimizedIndexes() {
        try {
            // Performance-optimized contact form indexes
            await mongoose.connection.db.collection('formdatas').createIndex(
                { 'Email': 1 },
                { background: true, unique: false }
            );
            await mongoose.connection.db.collection('formdatas').createIndex(
                { 'createdAt': -1 },
                { background: true }
            );

            // Compound index for pagination queries
            await mongoose.connection.db.collection('formdatas').createIndex(
                { 'createdAt': -1, '_id': 1 },
                { background: true }
            );

            // Text search index for contact search
            await mongoose.connection.db.collection('formdatas').createIndex(
                {
                    'FirstName': 'text',
                    'LastName': 'text',
                    'Email': 'text',
                    'Message': 'text'
                },
                { background: true, weights: { 'FirstName': 10, 'LastName': 10, 'Email': 5, 'Message': 1 } }
            );

            // Security logs indexes
            await mongoose.connection.db.collection('security_logs').createIndex(
                { 'timestamp': -1 },
                { background: true, expireAfterSeconds: 2592000 } // 30 days TTL
            );
            await mongoose.connection.db.collection('security_logs').createIndex(
                { 'meta.ip': 1, 'timestamp': -1 },
                { background: true }
            );

            // Refresh tokens indexes
            await mongoose.connection.db.collection('refreshtokens').createIndex(
                { 'token': 1 },
                { unique: true, background: true }
            );
            await mongoose.connection.db.collection('refreshtokens').createIndex(
                { 'expiresAt': 1 },
                { expireAfterSeconds: 0, background: true }
            );

            // Admin users indexes
            await mongoose.connection.db.collection('adminusers').createIndex(
                { 'username': 1 },
                { unique: true, background: true }
            );

            console.log('✅ Security indexes created');

        } catch (error) {
            console.error('❌ Index creation error:', error);
        }
    }

    // MongoDB User Creation Script (for production)
    static generateUserCreationScript() {
        return `
// MongoDB User Setup Script
// Run this in MongoDB shell for production security

use portfolioDB;

// Create application user with limited privileges
db.createUser({
    user: "portfolioApp",
    pwd: "CHANGE_THIS_PASSWORD_IN_PRODUCTION",
    roles: [
        {
            role: "readWrite",
            db: "portfolioDB"
        }
    ]
});

// Create read-only user for monitoring
db.createUser({
    user: "portfolioMonitor", 
    pwd: "CHANGE_THIS_PASSWORD_TOO",
    roles: [
        {
            role: "read",
            db: "portfolioDB"
        }
    ]
});

// Enable authentication
// Add to mongod.conf:
// security:
//   authorization: enabled
        `;
    }
}

module.exports = { DatabaseSecurity };
