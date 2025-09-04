const fs = require('fs');
const path = require('path');
const forge = require('node-forge');

class WindowsSSLGenerator {
    constructor() {
        this.sslDir = path.join(__dirname, 'config', 'ssl');
        this.certPath = path.join(this.sslDir, 'certificate.pem');
        this.keyPath = path.join(this.sslDir, 'private-key.pem');
    }

    ensureSSLDirectory() {
        if (!fs.existsSync(this.sslDir)) {
            fs.mkdirSync(this.sslDir, { recursive: true });
            console.log('✅ SSL directory created');
        }
    }

    generateSelfSignedCertificate() {
        try {
            this.ensureSSLDirectory();
            console.log('🔐 Generating self-signed SSL certificate using Node.js...');

            // Generate a key pair
            const keys = forge.pki.rsa.generateKeyPair(2048);
            
            // Create a certificate
            const cert = forge.pki.createCertificate();
            cert.publicKey = keys.publicKey;
            cert.serialNumber = '01';
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

            // Set certificate attributes
            const attrs = [{
                name: 'countryName',
                value: 'IN'
            }, {
                name: 'stateOrProvinceName',
                value: 'Maharashtra'
            }, {
                name: 'localityName',
                value: 'Mumbai'
            }, {
                name: 'organizationName',
                value: 'Portfolio'
            }, {
                name: 'organizationalUnitName',
                value: 'Development'
            }, {
                name: 'commonName',
                value: 'localhost'
            }];

            cert.setSubject(attrs);
            cert.setIssuer(attrs);

            // Add extensions
            cert.setExtensions([{
                name: 'basicConstraints',
                cA: true
            }, {
                name: 'keyUsage',
                keyCertSign: true,
                digitalSignature: true,
                nonRepudiation: true,
                keyEncipherment: true,
                dataEncipherment: true
            }, {
                name: 'extKeyUsage',
                serverAuth: true,
                clientAuth: true,
                codeSigning: true,
                emailProtection: true,
                timeStamping: true
            }, {
                name: 'nsCertType',
                client: true,
                server: true,
                email: true,
                objsign: true,
                sslCA: true,
                emailCA: true,
                objCA: true
            }, {
                name: 'subjectAltName',
                altNames: [{
                    type: 2, // DNS
                    value: 'localhost'
                }, {
                    type: 2, // DNS
                    value: '*.localhost'
                }, {
                    type: 7, // IP
                    ip: '127.0.0.1'
                }, {
                    type: 7, // IP
                    ip: '::1'
                }]
            }]);

            // Self-sign certificate
            cert.sign(keys.privateKey);

            // Convert to PEM format
            const certPem = forge.pki.certificateToPem(cert);
            const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

            // Write files
            fs.writeFileSync(this.certPath, certPem);
            fs.writeFileSync(this.keyPath, keyPem);

            console.log('✅ Self-signed SSL certificate generated successfully');
            console.log(`📁 Certificate: ${this.certPath}`);
            console.log(`🔑 Private Key: ${this.keyPath}`);
            console.log('🚀 Start HTTPS server with: npm run https');

            return true;
        } catch (error) {
            console.error('❌ Error generating certificate:', error.message);
            return false;
        }
    }

    verifyCertificate() {
        try {
            if (!fs.existsSync(this.certPath) || !fs.existsSync(this.keyPath)) {
                console.log('❌ SSL certificate files not found');
                return false;
            }

            const certPem = fs.readFileSync(this.certPath, 'utf8');
            const cert = forge.pki.certificateFromPem(certPem);

            console.log('✅ SSL certificate is valid');
            console.log('📋 Certificate details:');
            console.log(`   Subject: ${cert.subject.getField('CN').value}`);
            console.log(`   Valid From: ${cert.validity.notBefore}`);
            console.log(`   Valid To: ${cert.validity.notAfter}`);
            console.log(`   Serial: ${cert.serialNumber}`);

            return true;
        } catch (error) {
            console.error('❌ Certificate verification failed:', error.message);
            return false;
        }
    }

    getCertificatePaths() {
        return {
            cert: this.certPath,
            key: this.keyPath,
            exists: fs.existsSync(this.certPath) && fs.existsSync(this.keyPath)
        };
    }
}

// Auto-run if called directly
if (require.main === module) {
    const generator = new WindowsSSLGenerator();
    
    console.log('🔐 Windows SSL Certificate Generator');
    console.log('==================================\n');
    
    const paths = generator.getCertificatePaths();
    
    if (paths.exists) {
        console.log('📋 Existing certificates found');
        generator.verifyCertificate();
        console.log('\n🚀 Start HTTPS server with: npm run https');
    } else {
        generator.generateSelfSignedCertificate();
    }
}

module.exports = { WindowsSSLGenerator };
