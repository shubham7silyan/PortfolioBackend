const { body } = require('express-validator');
const xss = require('xss');

// Contact form validation rules
const contactValidationRules = [
  body('FirstName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .matches(/^[a-zA-Z\s\u00C0-\u017F]+$/) // Allow accented characters
    .withMessage('First name must be 2-50 characters and contain only letters'),
  body('LastName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .matches(/^[a-zA-Z\s\u00C0-\u017F]+$/)
    .withMessage('Last name must be 2-50 characters and contain only letters'),
  body('Email')
    .trim()
    .isEmail()
    .normalizeEmail({
      gmail_lowercase: true,
      gmail_remove_dots: false,
      gmail_remove_subaddress: false,
    })
    .isLength({ max: 254 }) // RFC 5321 limit
    .withMessage('Please provide a valid email address'),
  body('Message')
    .trim()
    .isLength({ min: 10, max: 2000 })
    .withMessage('Message must be between 10-2000 characters'),
];

// XSS Protection and Input Sanitization
const sanitizeInput = (data) => {
  const xssOptions = {
    whiteList: {}, // No HTML tags allowed
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script'],
  };

  return {
    FirstName: xss(data.FirstName?.toString().trim(), xssOptions),
    LastName: xss(data.LastName?.toString().trim(), xssOptions),
    Email: xss(data.Email?.toString().trim().toLowerCase(), xssOptions),
    Message: xss(data.Message?.toString().trim(), xssOptions),
  };
};

// Advanced Content Pattern Detection
const detectSuspiciousContent = (data) => {
  const suspiciousPatterns = [
    // SQL Injection patterns
    /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bCREATE\b|\bALTER\b)/i,
    /(\bUNION\b|\bOR\b\s+\d+=\d+|\bAND\b\s+\d+=\d+)/i,
    /(--|\/\*|\*\/|;)/,
    // XSS patterns
    /<script[^>]*>.*?<\/script>/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    // Command injection
    /(\||&|;|\$\(|\`)/,
    /(wget|curl|nc|netcat|bash|sh|cmd|powershell)/i,
    // Path traversal
    /(\.\.\/|\.\.\\)/,
    // Email injection
    /(\r\n|\n|\r)(to:|cc:|bcc:|subject:)/i,
  ];

  for (const field in data) {
    if (data[field]) {
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(data[field])) {
          return {
            suspicious: true,
            field,
            pattern: pattern.toString(),
          };
        }
      }
    }
  }

  return { suspicious: false };
};

// Email validation with additional checks
const validateEmail = (email) => {
  // Basic email regex
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailRegex.test(email)) {
    return { valid: false, reason: 'Invalid email format' };
  }

  // Check for suspicious patterns
  const suspiciousEmailPatterns = [
    /\+.*@/, // Plus addressing (can be used for bypass)
    /\.{2,}/, // Multiple consecutive dots
    /^\./, // Starting with dot
    /\.$/, // Ending with dot
    /@.*@/, // Multiple @ symbols
    /[<>]/, // Angle brackets
  ];

  for (const pattern of suspiciousEmailPatterns) {
    if (pattern.test(email)) {
      return { valid: false, reason: 'Suspicious email pattern detected' };
    }
  }

  // Check domain length (max 253 characters)
  const domain = email.split('@')[1];
  if (domain && domain.length > 253) {
    return { valid: false, reason: 'Domain name too long' };
  }

  // Check for common disposable email domains
  const disposableDomains = [
    '10minutemail.com',
    'tempmail.org',
    'guerrillamail.com',
    'mailinator.com',
    'yopmail.com',
    'throwaway.email',
  ];

  if (disposableDomains.includes(domain?.toLowerCase())) {
    return { valid: false, reason: 'Disposable email addresses not allowed' };
  }

  return { valid: true };
};

// Rate limit bypass detection
const detectRateLimitBypass = (req) => {
  const forwardedIPs = req.headers['x-forwarded-for'];
  const realIP = req.headers['x-real-ip'];
  const clientIP = req.ip;

  // Check for multiple forwarded IPs (potential proxy chaining)
  if (forwardedIPs && forwardedIPs.split(',').length > 3) {
    return {
      suspicious: true,
      reason: 'Multiple proxy chain detected',
      forwardedIPs: forwardedIPs.split(','),
    };
  }

  // Check for inconsistent IP headers
  if (realIP && clientIP && realIP !== clientIP) {
    return {
      suspicious: true,
      reason: 'IP header inconsistency',
      realIP,
      clientIP,
    };
  }

  return { suspicious: false };
};

module.exports = {
  contactValidationRules,
  sanitizeInput,
  detectSuspiciousContent,
  validateEmail,
  detectRateLimitBypass,
};
