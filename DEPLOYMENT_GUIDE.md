# 🚀 Advanced Security Portfolio Backend - Deployment Guide

## 🛡️ Security Features Implemented

### Core Security
- ✅ **JWT Authentication** with 15-minute access tokens and 7-day refresh tokens
- ✅ **bcrypt Password Hashing** with 12 salt rounds
- ✅ **Account Lockout** after 5 failed login attempts (30-minute lockout)
- ✅ **Dual Authentication** requiring both JWT and API key for admin routes
- ✅ **Rate Limiting** on all endpoints with IP-based and user-based limits
- ✅ **Input Sanitization** and XSS protection
- ✅ **CORS Security** with strict origin validation

### Advanced Security
- ✅ **Role-Based Access Control (RBAC)** with granular permissions
- ✅ **Immutable Append-Only Logging** with cryptographic integrity
- ✅ **Off-Site Log Storage** (CloudWatch, ELK, webhooks)
- ✅ **Per-User Token Rate Limiting** beyond IP-based limits
- ✅ **HMAC Request Signing** for critical API operations
- ✅ **Geo-IP Restrictions** for admin access (India-only by default)
- ✅ **Session Security** with IP validation and session tracking
- ✅ **HashiCorp Vault/AWS Secrets Manager** integration

## 🔧 Environment Setup

### Required Environment Variables
```bash
# Database
MONGODB_URI=mongodb://127.0.0.1:27017/portfolioDB
MONGODB_USERNAME=portfolioApp
MONGODB_PASSWORD=your_secure_password

# Email
GMAIL_USER=your_email@gmail.com
GMAIL_APP_PASSWORD=your_app_password

# JWT Secrets (32+ characters)
JWT_ACCESS_SECRET=your_jwt_access_secret_32_chars_min
JWT_REFRESH_SECRET=your_jwt_refresh_secret_32_chars_min

# Admin Credentials
ADMIN_PASSWORD=your_secure_admin_password
ADMIN_API_KEY=your_admin_api_key_32_chars_minimum

# Advanced Security
LOG_SIGNING_KEY=your_32_char_log_signing_key
HMAC_SIGNING_KEY=your_32_char_hmac_signing_key
ALLOWED_COUNTRIES=IN,US,GB
BLOCKED_COUNTRIES=CN,RU,KP,IR

# External Services (Optional)
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
AWS_REGION=us-east-1
VAULT_ENDPOINT=https://vault.example.com
VAULT_TOKEN=your_vault_token
LOG_WEBHOOK_URL=https://your-log-service.com/webhook
ELASTICSEARCH_URL=https://your-elasticsearch.com
```

## 🚀 Deployment Steps

### 1. Install Dependencies
```bash
cd NodeJs
npm install
```

### 2. Configure MongoDB
```bash
# Start MongoDB with authentication
mongod --auth --port 27017

# Create application user
mongo admin
db.createUser({
  user: "portfolioApp",
  pwd: "your_secure_password",
  roles: [
    { role: "readWrite", db: "portfolioDB" },
    { role: "dbAdmin", db: "portfolioDB" }
  ]
})
```

### 3. Generate Secure Keys
```bash
# Generate random 32-character keys
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 4. Configure Nginx (Production)
```bash
# Copy nginx.conf to /etc/nginx/sites-available/
sudo cp config/nginx.conf /etc/nginx/sites-available/portfolio
sudo ln -s /etc/nginx/sites-available/portfolio /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 5. Start Application
```bash
# Development
npm start

# Production with PM2
npm install -g pm2
pm2 start index.js --name "portfolio-backend"
pm2 startup
pm2 save
```

## 🧪 Security Testing

Run the comprehensive security test suite:
```bash
node test-security.js
```

### Manual Testing Checklist
- [ ] Rate limiting blocks excessive requests
- [ ] XSS attempts are blocked
- [ ] Invalid emails are rejected
- [ ] Admin login requires correct credentials
- [ ] Account locks after failed attempts
- [ ] JWT tokens expire correctly
- [ ] RBAC permissions are enforced
- [ ] HMAC signatures are verified
- [ ] Geo-IP restrictions work
- [ ] Immutable logs maintain integrity
- [ ] Security alerts are sent

## 📊 Monitoring & Alerts

### Log Locations
- **Local Files**: `logs/security.log`, `logs/error.log`
- **MongoDB**: `security_logs` collection
- **CloudWatch**: `portfolio-security-logs` log group
- **External**: Webhook/ELK endpoints

### Security Alerts
Automatic email alerts for:
- Failed login attempts
- Account lockouts
- Suspicious activities
- Rate limit violations
- Invalid signatures
- Geo-blocked access attempts

## 🔒 Security Best Practices

### Production Checklist
- [ ] Use strong, unique passwords (20+ characters)
- [ ] Enable MongoDB authentication
- [ ] Configure SSL/TLS certificates
- [ ] Set up Nginx reverse proxy
- [ ] Configure firewall rules
- [ ] Enable log rotation
- [ ] Set up monitoring dashboards
- [ ] Configure backup strategies
- [ ] Test disaster recovery
- [ ] Document incident response procedures

### API Usage

#### Admin Login
```bash
curl -X POST http://localhost:5050/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}'
```

#### Access Protected Route
```bash
curl -X GET http://localhost:5050/admin/contacts \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### HMAC-Signed Request
```bash
# Generate signature with timestamp and nonce
curl -X DELETE http://localhost:5050/admin/contacts/ID \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "x-signature: HMAC_SIGNATURE" \
  -H "x-timestamp: TIMESTAMP" \
  -H "x-nonce: RANDOM_NONCE"
```

## 🚨 Incident Response

### Security Breach Response
1. **Immediate**: Revoke all active tokens
2. **Assess**: Check immutable logs for breach scope
3. **Contain**: Block suspicious IPs
4. **Investigate**: Analyze off-site logs
5. **Recover**: Restore from secure backups
6. **Learn**: Update security measures

### Emergency Commands
```bash
# Revoke all tokens
db.refresh_tokens.deleteMany({})

# Block IP range
# Add to nginx.conf: deny IP_RANGE;

# Check log integrity
curl http://localhost:5050/admin/system/status
```

## 📈 Performance Considerations

- **Rate Limiting**: Adjust limits based on usage patterns
- **Database Indexes**: Monitor query performance
- **Log Rotation**: Configure to prevent disk space issues
- **Memory Usage**: Monitor for memory leaks in long-running processes
- **Connection Pooling**: Optimize MongoDB connection settings

## 🔄 Maintenance

### Regular Tasks
- Rotate JWT secrets monthly
- Review and update geo-IP restrictions
- Analyze security logs weekly
- Update dependencies quarterly
- Test backup/restore procedures monthly
- Review RBAC permissions quarterly

### Monitoring Metrics
- Failed login attempts per hour
- Rate limit violations per day
- Geographic distribution of requests
- Response times for protected routes
- Memory and CPU usage trends
- Log integrity verification status

---

**🎯 Your portfolio backend now has enterprise-grade security suitable for production deployment!**
