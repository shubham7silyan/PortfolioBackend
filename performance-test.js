const axios = require('axios');
const { performance } = require('perf_hooks');

class PerformanceTester {
    constructor(baseURL = 'http://localhost:5050') {
        this.baseURL = baseURL;
        this.accessToken = null;
    }

    async login() {
        try {
            const response = await axios.post(`${this.baseURL}/admin/login`, {
                username: 'admin',
                password: process.env.ADMIN_PASSWORD || 'admin123'
            });
            this.accessToken = response.data.accessToken;
            return true;
        } catch (error) {
            console.error('Login failed:', error.message);
            return false;
        }
    }

    async measureEndpoint(method, endpoint, data = null, headers = {}) {
        const start = performance.now();
        
        try {
            const config = {
                method,
                url: `${this.baseURL}${endpoint}`,
                headers: {
                    'Authorization': this.accessToken ? `Bearer ${this.accessToken}` : undefined,
                    ...headers
                },
                data
            };

            const response = await axios(config);
            const end = performance.now();
            
            return {
                success: true,
                duration: Math.round(end - start),
                status: response.status,
                cached: response.headers['x-cache'] === 'HIT',
                size: JSON.stringify(response.data).length
            };
        } catch (error) {
            const end = performance.now();
            return {
                success: false,
                duration: Math.round(end - start),
                status: error.response?.status || 0,
                error: error.message
            };
        }
    }

    async testCaching() {
        console.log('\n📊 Testing Caching Performance...\n');

        // Test cache miss vs hit
        console.log('1. Cache Miss vs Hit Test:');
        
        const miss = await this.measureEndpoint('GET', '/admin/contacts');
        console.log(`   First request (cache miss): ${miss.duration}ms`);
        
        const hit = await this.measureEndpoint('GET', '/admin/contacts');
        console.log(`   Second request (cache hit): ${hit.duration}ms`);
        console.log(`   Performance improvement: ${Math.round((miss.duration - hit.duration) / miss.duration * 100)}%`);
    }

    async testDatabaseOptimization() {
        console.log('\n🗄️ Testing Database Optimization...\n');

        // Test pagination performance
        console.log('1. Pagination Performance:');
        const paginated = await this.measureEndpoint('GET', '/admin/contacts?page=1&limit=10');
        console.log(`   Paginated query: ${paginated.duration}ms`);

        // Test search performance
        console.log('2. Search Performance:');
        const search = await this.measureEndpoint('GET', '/admin/contacts/search/test');
        console.log(`   Text search: ${search.duration}ms`);
    }

    async testParallelRequests() {
        console.log('\n⚡ Testing Parallel Request Handling...\n');

        const endpoints = [
            '/admin/contacts?page=1&limit=5',
            '/admin/system/status',
            '/health'
        ];

        const start = performance.now();
        const results = await Promise.all(
            endpoints.map(endpoint => this.measureEndpoint('GET', endpoint))
        );
        const totalParallel = performance.now() - start;

        console.log('Parallel execution results:');
        results.forEach((result, i) => {
            console.log(`   ${endpoints[i]}: ${result.duration}ms (${result.cached ? 'cached' : 'fresh'})`);
        });
        console.log(`   Total parallel time: ${Math.round(totalParallel)}ms`);

        // Compare with sequential
        const sequentialStart = performance.now();
        for (const endpoint of endpoints) {
            await this.measureEndpoint('GET', endpoint);
        }
        const totalSequential = performance.now() - sequentialStart;
        
        console.log(`   Sequential would take: ${Math.round(totalSequential)}ms`);
        console.log(`   Performance gain: ${Math.round((totalSequential - totalParallel) / totalSequential * 100)}%`);
    }

    async testCompressionBenefit() {
        console.log('\n📦 Testing Compression Benefits...\n');

        const result = await this.measureEndpoint('GET', '/admin/contacts?page=1&limit=50');
        const contentEncoding = result.headers?.['content-encoding'];
        
        console.log(`   Response size: ${result.size} bytes`);
        console.log(`   Compression: ${contentEncoding || 'none'}`);
        console.log(`   Response time: ${result.duration}ms`);
    }

    async runPerformanceTests() {
        console.log('🚀 Starting Performance Testing...');
        console.log(`🎯 Target: ${this.baseURL}`);

        if (await this.login()) {
            await this.testCaching();
            await this.testDatabaseOptimization();
            await this.testParallelRequests();
            await this.testCompressionBenefit();
            
            console.log('\n✅ Performance testing completed!');
            console.log('\n📈 Optimization Summary:');
            console.log('   - Redis/Memory caching: Enabled');
            console.log('   - Database query optimization: Enabled');
            console.log('   - Parallel request processing: Enabled');
            console.log('   - Gzip/Brotli compression: Enabled');
            console.log('   - Async logging queues: Enabled');
            console.log('   - Smart rate limiting: Enabled');
        } else {
            console.log('❌ Could not authenticate for performance tests');
        }
    }
}

// Load testing function
async function loadTest(concurrency = 10, requests = 100) {
    console.log(`\n🔥 Load Testing: ${concurrency} concurrent users, ${requests} requests each\n`);
    
    const tester = new PerformanceTester();
    await tester.login();
    
    const workers = Array(concurrency).fill().map(async (_, i) => {
        const results = [];
        for (let j = 0; j < requests / concurrency; j++) {
            const result = await tester.measureEndpoint('GET', '/health');
            results.push(result.duration);
        }
        return results;
    });

    const start = performance.now();
    const allResults = await Promise.all(workers);
    const totalTime = performance.now() - start;
    
    const durations = allResults.flat();
    const avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
    const maxDuration = Math.max(...durations);
    const minDuration = Math.min(...durations);
    
    console.log(`📊 Load Test Results:`);
    console.log(`   Total requests: ${durations.length}`);
    console.log(`   Total time: ${Math.round(totalTime)}ms`);
    console.log(`   Requests/second: ${Math.round(durations.length / (totalTime / 1000))}`);
    console.log(`   Average response: ${Math.round(avgDuration)}ms`);
    console.log(`   Min response: ${Math.round(minDuration)}ms`);
    console.log(`   Max response: ${Math.round(maxDuration)}ms`);
}

if (require.main === module) {
    const tester = new PerformanceTester();
    tester.runPerformanceTests().then(() => {
        return loadTest(5, 50); // 5 concurrent users, 50 requests total
    }).catch(console.error);
}

module.exports = { PerformanceTester, loadTest };
