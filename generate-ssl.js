#!/usr/bin/env node

const { SSLManager } = require('./config/ssl-setup');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

class SSLCertificateGenerator {
    constructor() {
        this.sslManager = new SSLManager();
    }

    async promptUser(question) {
        return new Promise((resolve) => {
            rl.question(question, (answer) => {
                resolve(answer.trim());
            });
        });
    }

    async generateCertificates() {
        console.log('🔐 SSL Certificate Setup for Portfolio Backend\n');

        const environment = await this.promptUser('Environment (development/production): ');

        if (environment.toLowerCase() === 'production') {
            await this.setupProductionSSL();
        } else {
            await this.setupDevelopmentSSL();
        }

        rl.close();
    }

    async setupDevelopmentSSL() {
        console.log('\n🛠️ Setting up development SSL certificates...\n');

        const success = this.sslManager.generateSelfSignedCertificate();

        if (success) {
            console.log('\n✅ Development SSL setup complete!');
            console.log('🚀 You can now start your HTTPS server with:');
            console.log('   node https-server.js');
            console.log('\n🌐 Access your portfolio at:');
            console.log('   https://localhost:443 (or your configured HTTPS_PORT)');
            console.log('\n⚠️ Note: Browsers will show a security warning for self-signed certificates');
            console.log('   Click "Advanced" → "Proceed to localhost" to continue');
        }
    }

    async setupProductionSSL() {
        console.log('\n🌐 Setting up production SSL certificates...\n');

        const domain = await this.promptUser('Domain name (e.g., portfolio.com): ');
        const email = await this.promptUser('Admin email for Let\'s Encrypt: ');

        console.log('\n📋 Production SSL Options:');
        console.log('1. Let\'s Encrypt (Free, automatic renewal)');
        console.log('2. Generate CSR for commercial certificate');
        console.log('3. Self-signed (for testing)');

        const choice = await this.promptUser('Choose option (1-3): ');

        switch (choice) {
        case '1':
            await this.setupLetsEncrypt(domain, email);
            break;
        case '2':
            await this.setupCommercialCSR(domain);
            break;
        case '3':
            this.sslManager.generateSelfSignedCertificate();
            break;
        default:
            console.log('❌ Invalid option');
            break;
        }
    }

    async setupLetsEncrypt(domain, email) {
        console.log('\n🌐 Setting up Let\'s Encrypt certificate...');
        console.log('⚠️ Requirements:');
        console.log('   - Domain must point to this server');
        console.log('   - Port 80 must be available');
        console.log('   - Certbot must be installed');

        const proceed = await this.promptUser('Continue? (y/n): ');

        if (proceed.toLowerCase() === 'y') {
            const success = await this.sslManager.setupLetsEncrypt(domain, email);

            if (success) {
                console.log('\n✅ Let\'s Encrypt certificate installed!');
                this.sslManager.setupAutoRenewal(domain);
                console.log('\n🚀 Start your server with:');
                console.log('   NODE_ENV=production node https-server.js');
            }
        }
    }

    async setupCommercialCSR(domain) {
        console.log('\n📝 Generating CSR for commercial certificate...');

        const success = this.sslManager.generateCSR(domain);

        if (success) {
            console.log('\n✅ CSR generated successfully!');
            console.log('\n📋 Next steps:');
            console.log('1. Submit the CSR to your Certificate Authority');
            console.log('2. Download the issued certificate');
            console.log('3. Replace the certificate.pem file with the issued certificate');
            console.log('4. Start your server with: NODE_ENV=production node https-server.js');
        }
    }

    // Quick setup for immediate development
    static quickSetup() {
        console.log('⚡ Quick SSL setup for development...');
        const sslManager = new SSLManager();
        const success = sslManager.generateSelfSignedCertificate();

        if (success) {
            console.log('✅ Quick setup complete! Run: node https-server.js');
        }

        return success;
    }
}

// Command line interface
if (require.main === module) {
    const args = process.argv.slice(2);

    if (args.includes('--quick') || args.includes('-q')) {
        SSLCertificateGenerator.quickSetup();
    } else {
        const generator = new SSLCertificateGenerator();
        generator.generateCertificates().catch(console.error);
    }
}

module.exports = { SSLCertificateGenerator };
