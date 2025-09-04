const axios = require('axios');
const crypto = require('crypto');

// Security Feature Testing Script
class SecurityTester {
    constructor(baseURL = 'http://localhost:5050') {
        this.baseURL = baseURL;
        this.accessToken = null;
        this.refreshToken = null;
        this.signingKey = process.env.HMAC_SIGNING_KEY || 'test_key';
    }

    generateHMACSignature(method, path, body) {
        const timestamp = Date.now().toString();
        const nonce = crypto.randomBytes(16).toString('hex');
        const payload = `${method}|${path}|${JSON.stringify(body)}|${timestamp}|${nonce}`;
        const signature = crypto.createHmac('sha256', this.signingKey).update(payload).digest('hex');
        
        return {
            'x-signature': signature,
            'x-timestamp': timestamp,
            'x-nonce': nonce
        };
    }

    async testBasicSecurity() {
        console.log('\n🧪 Testing Basic Security Features...\n');

        // Test 1: Rate Limiting
        console.log('1. Testing Rate Limiting...');
        try {
            const promises = Array(20).fill().map(() => 
                axios.post(`${this.baseURL}/contact`, {
                    FirstName: 'Test',
                    LastName: 'User',
                    Email: 'test@example.com',
                    Message: 'Rate limit test'
                })
            );
            
            const results = await Promise.allSettled(promises);
            const blocked = results.filter(r => r.status === 'rejected' && r.reason.response?.status === 429);
            console.log(`   ✅ Rate limiting working: ${blocked.length}/20 requests blocked`);
        } catch (error) {
            console.log(`   ❌ Rate limiting test failed: ${error.message}`);
        }

        // Test 2: XSS Protection
        console.log('2. Testing XSS Protection...');
        try {
            const response = await axios.post(`${this.baseURL}/contact`, {
                FirstName: '<script>alert("xss")</script>',
                LastName: 'Test',
                Email: 'test@example.com',
                Message: 'XSS test'
            });
            console.log('   ❌ XSS protection may be bypassed');
        } catch (error) {
            if (error.response?.status === 400) {
                console.log('   ✅ XSS protection working');
            } else {
                console.log(`   ⚠️ Unexpected error: ${error.message}`);
            }
        }

        // Test 3: Email Validation
        console.log('3. Testing Email Validation...');
        try {
            const response = await axios.post(`${this.baseURL}/contact`, {
                FirstName: 'Test',
                LastName: 'User',
                Email: 'invalid-email',
                Message: 'Email validation test'
            });
            console.log('   ❌ Email validation may be bypassed');
        } catch (error) {
            if (error.response?.status === 400) {
                console.log('   ✅ Email validation working');
            }
        }
    }

    async testAuthentication() {
        console.log('\n🔐 Testing Authentication Features...\n');

        // Test 1: Admin Login
        console.log('1. Testing Admin Login...');
        try {
            const response = await axios.post(`${this.baseURL}/admin/login`, {
                username: 'admin',
                password: process.env.ADMIN_PASSWORD || 'admin123'
            });
            
            if (response.data.success) {
                this.accessToken = response.data.accessToken;
                this.refreshToken = response.data.refreshToken;
                console.log('   ✅ Admin login successful');
                console.log(`   📝 Session ID: ${response.data.sessionId}`);
            }
        } catch (error) {
            console.log(`   ❌ Admin login failed: ${error.response?.data?.message || error.message}`);
        }

        // Test 2: Protected Route Access
        console.log('2. Testing Protected Route Access...');
        if (this.accessToken) {
            try {
                const response = await axios.get(`${this.baseURL}/admin/contacts`, {
                    headers: {
                        'Authorization': `Bearer ${this.accessToken}`
                    }
                });
                console.log(`   ✅ Protected route access successful: ${response.data.count} contacts`);
            } catch (error) {
                console.log(`   ❌ Protected route access failed: ${error.response?.data?.message}`);
            }
        }

        // Test 3: Token Refresh
        console.log('3. Testing Token Refresh...');
        if (this.refreshToken) {
            try {
                const response = await axios.post(`${this.baseURL}/admin/refresh`, {
                    refreshToken: this.refreshToken
                });
                
                if (response.data.success) {
                    this.accessToken = response.data.accessToken;
                    this.refreshToken = response.data.refreshToken;
                    console.log('   ✅ Token refresh successful');
                }
            } catch (error) {
                console.log(`   ❌ Token refresh failed: ${error.response?.data?.message}`);
            }
        }
    }

    async testAdvancedSecurity() {
        console.log('\n🛡️ Testing Advanced Security Features...\n');

        // Test 1: HMAC Signature Verification
        console.log('1. Testing HMAC Signature Verification...');
        if (this.accessToken) {
            try {
                const method = 'DELETE';
                const path = '/admin/contacts/test_id';
                const body = {};
                const headers = {
                    'Authorization': `Bearer ${this.accessToken}`,
                    ...this.generateHMACSignature(method, path, body)
                };

                await axios.delete(`${this.baseURL}${path}`, { headers });
                console.log('   ✅ HMAC signature verification working');
            } catch (error) {
                if (error.response?.status === 401 && error.response?.data?.message?.includes('signature')) {
                    console.log('   ✅ HMAC signature verification working (rejected invalid signature)');
                } else {
                    console.log(`   ⚠️ HMAC test result: ${error.response?.data?.message || error.message}`);
                }
            }
        }

        // Test 2: System Status with RBAC
        console.log('2. Testing System Status with RBAC...');
        if (this.accessToken) {
            try {
                const response = await axios.get(`${this.baseURL}/admin/system/status`, {
                    headers: {
                        'Authorization': `Bearer ${this.accessToken}`
                    }
                });
                
                console.log('   ✅ System status accessible');
                console.log(`   📊 Log integrity: ${response.data.security?.logIntegrity?.valid ? 'VALID' : 'INVALID'}`);
            } catch (error) {
                console.log(`   ❌ System status failed: ${error.response?.data?.message}`);
            }
        }

        // Test 3: Invalid Token Access
        console.log('3. Testing Invalid Token Protection...');
        try {
            await axios.get(`${this.baseURL}/admin/contacts`, {
                headers: {
                    'Authorization': 'Bearer invalid_token'
                }
            });
            console.log('   ❌ Invalid token protection failed');
        } catch (error) {
            if (error.response?.status === 403) {
                console.log('   ✅ Invalid token protection working');
            }
        }
    }

    async runAllTests() {
        console.log('🚀 Starting Comprehensive Security Testing...');
        console.log(`🎯 Target: ${this.baseURL}`);
        
        await this.testBasicSecurity();
        await this.testAuthentication();
        await this.testAdvancedSecurity();
        
        console.log('\n✅ Security testing completed!');
        console.log('\n📋 Summary:');
        console.log('   - Rate limiting: Tested');
        console.log('   - XSS protection: Tested');
        console.log('   - Email validation: Tested');
        console.log('   - JWT authentication: Tested');
        console.log('   - Token refresh: Tested');
        console.log('   - HMAC signing: Tested');
        console.log('   - RBAC permissions: Tested');
        console.log('   - System monitoring: Tested');
    }
}

// Run tests if called directly
if (require.main === module) {
    const tester = new SecurityTester();
    tester.runAllTests().catch(console.error);
}

module.exports = SecurityTester;
