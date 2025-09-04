const vault = require('node-vault');
const AWS = require('aws-sdk');

// HashiCorp Vault Configuration
class VaultManager {
    constructor() {
        this.vault = vault({
            apiVersion: 'v1',
            endpoint: process.env.VAULT_ENDPOINT || 'http://127.0.0.1:8200',
            token: process.env.VAULT_TOKEN
        });
        this.secretCache = new Map();
        this.cacheExpiry = 5 * 60 * 1000; // 5 minutes cache
    }

    async getSecret(path) {
        const cacheKey = path;
        const cached = this.secretCache.get(cacheKey);

        if (cached && Date.now() - cached.timestamp < this.cacheExpiry) {
            return cached.data;
        }

        try {
            const result = await this.vault.read(path);
            const secretData = result.data.data || result.data;

            this.secretCache.set(cacheKey, {
                data: secretData,
                timestamp: Date.now()
            });

            return secretData;
        } catch (error) {
            console.error('❌ Vault secret retrieval failed:', error);
            throw new Error('Secret retrieval failed');
        }
    }

    async rotateSecret(path, newSecret) {
        try {
            await this.vault.write(path, { data: newSecret });
            this.secretCache.delete(path); // Invalidate cache
            console.log(`✅ Secret rotated: ${path}`);
        } catch (error) {
            console.error('❌ Secret rotation failed:', error);
            throw error;
        }
    }
}

// AWS Secrets Manager Configuration
class AWSSecretsManager {
    constructor() {
        this.secretsManager = new AWS.SecretsManager({
            region: process.env.AWS_REGION || 'us-east-1',
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
        });
        this.secretCache = new Map();
        this.cacheExpiry = 5 * 60 * 1000; // 5 minutes cache
    }

    async getSecret(secretName) {
        const cached = this.secretCache.get(secretName);

        if (cached && Date.now() - cached.timestamp < this.cacheExpiry) {
            return cached.data;
        }

        try {
            const result = await this.secretsManager.getSecretValue({
                SecretId: secretName
            }).promise();

            const secretData = JSON.parse(result.SecretString);

            this.secretCache.set(secretName, {
                data: secretData,
                timestamp: Date.now()
            });

            return secretData;
        } catch (error) {
            console.error('❌ AWS Secrets Manager retrieval failed:', error);
            throw new Error('Secret retrieval failed');
        }
    }

    async rotateSecret(secretName, newSecret) {
        try {
            await this.secretsManager.updateSecret({
                SecretId: secretName,
                SecretString: JSON.stringify(newSecret)
            }).promise();

            this.secretCache.delete(secretName); // Invalidate cache
            console.log(`✅ AWS Secret rotated: ${secretName}`);
        } catch (error) {
            console.error('❌ AWS Secret rotation failed:', error);
            throw error;
        }
    }
}

// Unified Secrets Manager
class SecretsManager {
    constructor() {
        this.provider = process.env.SECRETS_PROVIDER || 'vault'; // 'vault' or 'aws'

        if (this.provider === 'vault') {
            this.manager = new VaultManager();
        } else if (this.provider === 'aws') {
            this.manager = new AWSSecretsManager();
        } else {
            throw new Error('Invalid secrets provider. Use "vault" or "aws"');
        }
    }

    async getSecret(path) {
        return await this.manager.getSecret(path);
    }

    async rotateSecret(path, newSecret) {
        return await this.manager.rotateSecret(path, newSecret);
    }

    // Get application secrets
    async getAppSecrets() {
        try {
            if (this.provider === 'vault') {
                return await this.getSecret('secret/portfolio/app');
            } else {
                return await this.getSecret('portfolio/app-secrets');
            }
        } catch (error) {
            console.warn('⚠️ Falling back to environment variables');
            return {
                JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET,
                JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
                ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
                ADMIN_API_KEY: process.env.ADMIN_API_KEY,
                GMAIL_APP_PASSWORD: process.env.GMAIL_APP_PASSWORD,
                MONGODB_PASSWORD: process.env.MONGODB_PASSWORD
            };
        }
    }

    // Automatic secret rotation (for production)
    async rotateAllSecrets() {
        const crypto = require('crypto');

        const newSecrets = {
            JWT_ACCESS_SECRET: crypto.randomBytes(32).toString('hex'),
            JWT_REFRESH_SECRET: crypto.randomBytes(32).toString('hex'),
            ADMIN_API_KEY: crypto.randomBytes(32).toString('hex')
        };

        try {
            if (this.provider === 'vault') {
                await this.rotateSecret('secret/portfolio/app', newSecrets);
            } else {
                await this.rotateSecret('portfolio/app-secrets', newSecrets);
            }

            console.log('✅ All secrets rotated successfully');
            return newSecrets;
        } catch (error) {
            console.error('❌ Secret rotation failed:', error);
            throw error;
        }
    }
}

module.exports = { SecretsManager, VaultManager, AWSSecretsManager };
