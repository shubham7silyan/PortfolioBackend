// CDN and Static Asset Optimization Configuration
const express = require('express');
const path = require('path');

class CDNConfig {
    static setupStaticAssets(app) {
        // Serve static files with aggressive caching
        app.use('/static', express.static(path.join(__dirname, '../public'), {
            maxAge: '1y', // Cache for 1 year
            etag: true,
            lastModified: true,
            setHeaders: (res, filePath) => {
                // Set specific cache headers based on file type
                if (filePath.endsWith('.css') || filePath.endsWith('.js')) {
                    res.set('Cache-Control', 'public, max-age=31536000, immutable');
                } else if (filePath.match(/\.(jpg|jpeg|png|gif|webp|avif)$/)) {
                    res.set('Cache-Control', 'public, max-age=31536000');
                } else if (filePath.match(/\.(woff|woff2|ttf|eot)$/)) {
                    res.set('Cache-Control', 'public, max-age=31536000');
                    res.set('Access-Control-Allow-Origin', '*');
                }
            }
        }));

        // DNS prefetch and preconnect headers
        app.use((req, res, next) => {
            if (req.path === '/') {
                res.set('Link', [
                    '<https://fonts.googleapis.com>; rel=dns-prefetch',
                    '<https://fonts.gstatic.com>; rel=preconnect; crossorigin',
                    '<https://cdnjs.cloudflare.com>; rel=dns-prefetch'
                ].join(', '));
            }
            next();
        });
    }

    // Cloudflare configuration recommendations
    static getCloudflareConfig() {
        return {
            caching: {
                "*.css": "1y",
                "*.js": "1y", 
                "*.png": "1y",
                "*.jpg": "1y",
                "*.webp": "1y",
                "*.woff2": "1y",
                "/api/*": "0s", // Don't cache API responses
                "/admin/*": "0s" // Don't cache admin routes
            },
            compression: {
                level: 6,
                types: ['text/html', 'text/css', 'application/javascript', 'application/json']
            },
            minification: {
                css: true,
                js: true,
                html: true
            },
            security: {
                ssl: "strict",
                hsts: true,
                waf: true
            }
        };
    }
}

module.exports = { CDNConfig };
