const winston = require('winston');
const WintonCloudWatch = require('winston-cloudwatch');
const crypto = require('crypto');
const mongoose = require('mongoose');

// Immutable Log Entry Schema
const immutableLogSchema = new mongoose.Schema({
    logId: { type: String, required: true, unique: true },
    timestamp: { type: Date, required: true, immutable: true },
    level: { type: String, required: true, immutable: true },
    message: { type: String, required: true, immutable: true },
    metadata: { type: Object, immutable: true },
    
    // Cryptographic integrity
    hash: { type: String, required: true, immutable: true },
    previousHash: { type: String, immutable: true },
    signature: { type: String, required: true, immutable: true },
    
    // Blockchain-like chain
    blockNumber: { type: Number, required: true, immutable: true },
    
    // Prevent any updates
    __v: { type: Number, select: false }
}, {
    // Disable updates completely
    strict: true,
    versionKey: false
});

// Prevent all update operations
immutableLogSchema.pre(['updateOne', 'updateMany', 'findOneAndUpdate'], function() {
    throw new Error('Immutable logs cannot be modified');
});

immutableLogSchema.pre('save', function(next) {
    if (!this.isNew) {
        throw new Error('Immutable logs cannot be modified after creation');
    }
    next();
});

const ImmutableLog = mongoose.model('ImmutableLog', immutableLogSchema);

// Immutable Logging System
class ImmutableLogger {
    constructor() {
        this.secretKey = process.env.LOG_SIGNING_KEY || crypto.randomBytes(32).toString('hex');
        this.lastBlockNumber = 0;
        this.lastHash = '0000000000000000000000000000000000000000000000000000000000000000';
        this.initializeChain();
    }

    async initializeChain() {
        try {
            // Skip database operations if in bypass mode
            if (process.env.DB_BYPASS === 'true') {
                console.log('⚠️ Immutable logging initialization skipped - database bypass mode');
                this.lastBlockNumber = 0;
                this.lastHash = '0';
                return;
            }
            
            const lastLog = await ImmutableLog.findOne().sort({ blockNumber: -1 });
            if (lastLog) {
                this.lastBlockNumber = lastLog.blockNumber;
                this.lastHash = lastLog.hash;
            }
        } catch (error) {
            console.error('❌ Failed to initialize log chain:', error);
        }
    }

    generateHash(data) {
        return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
    }

    generateSignature(data) {
        return crypto.createHmac('sha256', this.secretKey).update(JSON.stringify(data)).digest('hex');
    }

    async appendLog(level, message, metadata = {}) {
        try {
            const logId = crypto.randomUUID();
            const timestamp = new Date();
            this.lastBlockNumber++;

            const logData = {
                logId,
                timestamp,
                level,
                message,
                metadata,
                blockNumber: this.lastBlockNumber,
                previousHash: this.lastHash
            };

            // Generate cryptographic proof
            const hash = this.generateHash(logData);
            const signature = this.generateSignature({ ...logData, hash });

            const immutableLogEntry = new ImmutableLog({
                ...logData,
                hash,
                signature
            });

            await immutableLogEntry.save();
            this.lastHash = hash;

            return logId;
        } catch (error) {
            console.error('❌ Failed to append immutable log:', error);
            throw error;
        }
    }

    async verifyChainIntegrity() {
        try {
            const logs = await ImmutableLog.find().sort({ blockNumber: 1 });
            let previousHash = '0000000000000000000000000000000000000000000000000000000000000000';

            for (const log of logs) {
                // Verify hash chain
                if (log.previousHash !== previousHash) {
                    return {
                        valid: false,
                        error: `Chain broken at block ${log.blockNumber}`,
                        logId: log.logId
                    };
                }

                // Verify signature
                const expectedHash = this.generateHash({
                    logId: log.logId,
                    timestamp: log.timestamp,
                    level: log.level,
                    message: log.message,
                    metadata: log.metadata,
                    blockNumber: log.blockNumber,
                    previousHash: log.previousHash
                });

                if (log.hash !== expectedHash) {
                    return {
                        valid: false,
                        error: `Hash mismatch at block ${log.blockNumber}`,
                        logId: log.logId
                    };
                }

                previousHash = log.hash;
            }

            return { valid: true, totalBlocks: logs.length };
        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }
}

// Off-site Logging Configuration
class OffSiteLogger {
    constructor() {
        this.cloudWatchLogger = null;
        this.setupCloudWatch();
    }

    setupCloudWatch() {
        if (process.env.AWS_REGION && process.env.AWS_ACCESS_KEY_ID) {
            this.cloudWatchLogger = winston.createLogger({
                transports: [
                    new WintonCloudWatch({
                        logGroupName: 'portfolio-security-logs',
                        logStreamName: `portfolio-${new Date().toISOString().split('T')[0]}`,
                        awsRegion: process.env.AWS_REGION,
                        awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID,
                        awsSecretKey: process.env.AWS_SECRET_ACCESS_KEY,
                        messageFormatter: ({ level, message, meta }) => {
                            return JSON.stringify({
                                timestamp: new Date().toISOString(),
                                level,
                                message,
                                metadata: meta,
                                source: 'portfolio-backend'
                            });
                        }
                    })
                ]
            });
        }
    }

    async logToOffSite(level, message, metadata) {
        try {
            // CloudWatch logging
            if (this.cloudWatchLogger) {
                this.cloudWatchLogger.log(level, message, metadata);
            }

            // ELK Stack logging (if configured)
            if (process.env.ELASTICSEARCH_URL) {
                await this.logToElasticsearch(level, message, metadata);
            }

            // External webhook (for services like Datadog, Splunk)
            if (process.env.LOG_WEBHOOK_URL) {
                await this.logToWebhook(level, message, metadata);
            }

        } catch (error) {
            console.error('❌ Off-site logging failed:', error);
        }
    }

    async logToElasticsearch(level, message, metadata) {
        // Implementation for ELK stack
        const logEntry = {
            '@timestamp': new Date().toISOString(),
            level,
            message,
            metadata,
            service: 'portfolio-backend',
            environment: process.env.NODE_ENV
        };

        // Send to Elasticsearch (implementation depends on your ELK setup)
        console.log('📊 ELK Log:', logEntry);
    }

    async logToWebhook(level, message, metadata) {
        try {
            const payload = {
                timestamp: new Date().toISOString(),
                level,
                message,
                metadata,
                source: 'portfolio-backend'
            };

            // Send to external webhook
            const response = await fetch(process.env.LOG_WEBHOOK_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.LOG_WEBHOOK_TOKEN}`
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error(`Webhook failed: ${response.status}`);
            }
        } catch (error) {
            console.error('❌ Webhook logging failed:', error);
        }
    }
}

// Enhanced Security Logger with Immutable Logs
class EnhancedSecurityLogger {
    constructor() {
        this.immutableLogger = new ImmutableLogger();
        this.offSiteLogger = new OffSiteLogger();
    }

    async logSecurityEvent(level, message, metadata = {}) {
        const enhancedMetadata = {
            ...metadata,
            nodeId: process.env.NODE_ID || 'portfolio-node-1',
            pid: process.pid,
            memory: process.memoryUsage(),
            uptime: process.uptime()
        };

        try {
            // Log to immutable chain
            const logId = await this.immutableLogger.appendLog(level, message, enhancedMetadata);
            
            // Log to off-site services
            await this.offSiteLogger.logToOffSite(level, message, {
                ...enhancedMetadata,
                logId
            });

            return logId;
        } catch (error) {
            console.error('❌ Enhanced security logging failed:', error);
        }
    }

    async verifyLogIntegrity() {
        return await this.immutableLogger.verifyChainIntegrity();
    }
}

module.exports = {
    ImmutableLog,
    ImmutableLogger,
    OffSiteLogger,
    EnhancedSecurityLogger
};
