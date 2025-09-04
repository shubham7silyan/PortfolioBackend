const redis = require('redis');
const compression = require('compression');
const cluster = require('cluster');
const os = require('os');

// Redis Cache Manager
class CacheManager {
    constructor() {
        this.client = null;
        this.isConnected = false;
        // Only initialize Redis if explicitly enabled
        if (process.env.REDIS_ENABLED === 'true') {
            this.initRedis();
        } else {
            console.log('ℹ️ Redis caching disabled - using memory cache fallback');
            this.setupMemoryCache();
        }
    }

    async initRedis() {
        try {
            this.client = redis.createClient({
                host: process.env.REDIS_HOST || 'localhost',
                port: process.env.REDIS_PORT || 6379,
                password: process.env.REDIS_PASSWORD,
                db: process.env.REDIS_DB || 0,
                retry_strategy: (options) => {
                    if (options.error && options.error.code === 'ECONNREFUSED') {
                        console.log('⚠️ Redis server connection refused - using memory cache');
                        return false; // Stop retrying
                    }
                    if (options.total_retry_time > 1000 * 60 * 60) {
                        return new Error('Redis retry time exhausted');
                    }
                    return Math.min(options.attempt * 100, 3000);
                }
            });

            this.client.on('connect', () => {
                console.log('✅ Redis connected');
                this.isConnected = true;
            });

            this.client.on('error', (err) => {
                console.log('❌ Redis error:', err);
                this.isConnected = false;
                this.setupMemoryCache();
            });

            await this.client.connect();
        } catch (error) {
            console.log('⚠️ Redis unavailable, using memory cache fallback');
            this.setupMemoryCache();
        }
    }

    setupMemoryCache() {
        this.memoryCache = new Map();

        // Cleanup memory cache every 5 minutes
        setInterval(() => {
            const now = Date.now();
            for (const [key, value] of this.memoryCache.entries()) {
                if (value.expiry && value.expiry < now) {
                    this.memoryCache.delete(key);
                }
            }
        }, 5 * 60 * 1000);
    }

    async get(key) {
        try {
            if (this.isConnected) {
                const value = await this.client.get(key);
                return value ? JSON.parse(value) : null;
            } else if (this.memoryCache) {
                const cached = this.memoryCache.get(key);
                if (cached && (!cached.expiry || cached.expiry > Date.now())) {
                    return cached.value;
                }
                return null;
            }
        } catch (error) {
            console.error('Cache get error:', error);
            return null;
        }
    }

    async set(key, value, ttlSeconds = 60) {
        try {
            if (this.isConnected) {
                await this.client.setEx(key, ttlSeconds, JSON.stringify(value));
            } else if (this.memoryCache) {
                this.memoryCache.set(key, {
                    value,
                    expiry: Date.now() + (ttlSeconds * 1000)
                });
            }
        } catch (error) {
            console.error('Cache set error:', error);
        }
    }

    async del(key) {
        try {
            if (this.isConnected) {
                await this.client.del(key);
            } else if (this.memoryCache) {
                this.memoryCache.delete(key);
            }
        } catch (error) {
            console.error('Cache delete error:', error);
        }
    }

    // Cache middleware factory
    cacheMiddleware(ttlSeconds = 60, keyGenerator = null) {
        return async (req, res, next) => {
            const cacheKey = keyGenerator ?
                keyGenerator(req) :
                `${req.method}:${req.originalUrl}:${req.user?.userId || 'anonymous'}`;

            try {
                const cached = await this.get(cacheKey);
                if (cached) {
                    res.set('X-Cache', 'HIT');
                    return res.json(cached);
                }

                // Override res.json to cache response
                const originalJson = res.json;
                res.json = function(data) {
                    if (res.statusCode === 200) {
                        cacheManager.set(cacheKey, data, ttlSeconds);
                    }
                    res.set('X-Cache', 'MISS');
                    return originalJson.call(this, data);
                };

                next();
            } catch (error) {
                console.error('Cache middleware error:', error);
                next();
            }
        };
    }
}

// Performance Monitoring
class PerformanceMonitor {
    constructor() {
        this.metrics = {
            requests: 0,
            responses: new Map(),
            dbQueries: 0,
            cacheHits: 0,
            cacheMisses: 0
        };
    }

    trackRequest(req, res, next) {
        const start = Date.now();
        this.metrics.requests++;

        res.on('finish', () => {
            const duration = Date.now() - start;
            const route = `${req.method} ${req.route?.path || req.path}`;

            if (!this.metrics.responses.has(route)) {
                this.metrics.responses.set(route, []);
            }

            this.metrics.responses.get(route).push({
                duration,
                status: res.statusCode,
                timestamp: new Date()
            });

            // Log slow requests
            if (duration > 1000) {
                console.log(`🐌 Slow request: ${route} took ${duration}ms`);
            }
        });

        next();
    }

    getMetrics() {
        const routeStats = {};
        for (const [route, responses] of this.metrics.responses.entries()) {
            const durations = responses.map(r => r.duration);
            routeStats[route] = {
                count: responses.length,
                avgDuration: durations.reduce((a, b) => a + b, 0) / durations.length,
                maxDuration: Math.max(...durations),
                minDuration: Math.min(...durations)
            };
        }

        return {
            totalRequests: this.metrics.requests,
            routeStats,
            dbQueries: this.metrics.dbQueries,
            cacheHitRate: this.metrics.cacheHits / (this.metrics.cacheHits + this.metrics.cacheMisses) || 0,
            uptime: process.uptime(),
            memory: process.memoryUsage()
        };
    }
}

// Database Query Optimizer
class QueryOptimizer {
    static optimizeContactQueries() {
        return {
            // Optimized contact list with pagination
            getContacts: async (page = 1, limit = 20, sortBy = 'createdAt') => {
                const skip = (page - 1) * limit;
                return await UserModel
                    .find({}, 'FirstName LastName Email createdAt') // Select only needed fields
                    .sort({ [sortBy]: -1 })
                    .skip(skip)
                    .limit(limit)
                    .lean() // Return plain objects, not Mongoose documents
                    .exec();
            },

            // Count with cache
            getContactCount: async () => {
                return await UserModel.countDocuments().exec();
            },

            // Search with text index
            searchContacts: async (query, limit = 10) => {
                return await UserModel
                    .find({
                        $or: [
                            { FirstName: { $regex: query, $options: 'i' } },
                            { LastName: { $regex: query, $options: 'i' } },
                            { Email: { $regex: query, $options: 'i' } }
                        ]
                    })
                    .limit(limit)
                    .lean()
                    .exec();
            }
        };
    }
}

// Async Queue for Non-Critical Operations
class AsyncQueue {
    constructor() {
        this.queue = [];
        this.processing = false;
        this.processQueue();
    }

    add(task) {
        this.queue.push(task);
        if (!this.processing) {
            this.processQueue();
        }
    }

    async processQueue() {
        if (this.processing || this.queue.length === 0) {
            return;
        }

        this.processing = true;

        while (this.queue.length > 0) {
            const task = this.queue.shift();
            try {
                await task();
            } catch (error) {
                console.error('Queue task failed:', error);
            }
        }

        this.processing = false;
    }

    // Add email alerts to queue instead of blocking requests
    queueSecurityAlert(alertData) {
        this.add(async () => {
            const { securityAlertSystem } = require('./logging');
            await securityAlertSystem.sendAlert(alertData);
        });
    }

    // Add logging to queue
    queueLog(logData) {
        this.add(async () => {
            const { enhancedLogger } = require('./geo-security');
            await enhancedLogger.logSecurityEvent(logData.level, logData.message, logData.metadata);
        });
    }
}

// Cluster Management
class ClusterManager {
    static setupCluster() {
        const numCPUs = os.cpus().length;

        if (cluster.isMaster) {
            console.log(`🚀 Master process ${process.pid} starting ${numCPUs} workers`);

            // Fork workers
            for (let i = 0; i < numCPUs; i++) {
                cluster.fork();
            }

            cluster.on('exit', (worker, code, signal) => {
                console.log(`Worker ${worker.process.pid} died. Restarting...`);
                cluster.fork();
            });

            return false; // Don't start Express in master
        } else {
            console.log(`🔧 Worker ${process.pid} started`);
            return true; // Start Express in worker
        }
    }
}

// Initialize global instances
const cacheManager = new CacheManager();
const performanceMonitor = new PerformanceMonitor();
const asyncQueue = new AsyncQueue();

module.exports = {
    CacheManager,
    PerformanceMonitor,
    QueryOptimizer,
    AsyncQueue,
    ClusterManager,
    cacheManager,
    performanceMonitor,
    asyncQueue,
    compression
};
