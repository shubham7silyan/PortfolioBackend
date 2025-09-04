const http2 = require('http2');
const fs = require('fs');
const path = require('path');

// HTTP/2 Server Configuration
class HTTP2Server {
    static createSecureServer(app) {
        try {
            // SSL certificate paths (you'll need to generate these)
            const options = {
                key: fs.readFileSync(path.join(__dirname, 'ssl', 'private-key.pem')),
                cert: fs.readFileSync(path.join(__dirname, 'ssl', 'certificate.pem')),
                // HTTP/2 specific options
                allowHTTP1: true, // Fallback to HTTP/1.1 if needed
                settings: {
                    enablePush: true, // Enable server push
                    maxConcurrentStreams: 100,
                    maxHeaderListSize: 8192,
                    initialWindowSize: 65535
                }
            };

            const server = http2.createSecureServer(options, app);
            
            // Server push for critical resources
            server.on('stream', (stream, headers) => {
                if (headers[':path'] === '/') {
                    // Push critical CSS and JS files
                    stream.pushStream({
                        ':path': '/static/css/main.css',
                        ':method': 'GET'
                    }, (err, pushStream) => {
                        if (!err) {
                            pushStream.respondWithFile(
                                path.join(__dirname, '../public/static/css/main.css'),
                                { 'content-type': 'text/css' }
                            );
                        }
                    });

                    stream.pushStream({
                        ':path': '/static/js/main.js',
                        ':method': 'GET'
                    }, (err, pushStream) => {
                        if (!err) {
                            pushStream.respondWithFile(
                                path.join(__dirname, '../public/static/js/main.js'),
                                { 'content-type': 'application/javascript' }
                            );
                        }
                    });
                }
            });

            return server;
        } catch (error) {
            console.log('⚠️ HTTP/2 not available, falling back to HTTP/1.1');
            console.log('To enable HTTP/2, generate SSL certificates:');
            console.log('openssl req -x509 -newkey rsa:2048 -nodes -sha256 -subj "/CN=localhost" -keyout private-key.pem -out certificate.pem');
            return null;
        }
    }

    static setupServerPush(app) {
        // Middleware to add Link headers for HTTP/2 push
        app.use((req, res, next) => {
            if (req.path === '/') {
                res.set('Link', [
                    '</static/css/main.css>; rel=preload; as=style',
                    '</static/js/main.js>; rel=preload; as=script',
                    '</static/fonts/main.woff2>; rel=preload; as=font; type=font/woff2; crossorigin'
                ].join(', '));
            }
            next();
        });
    }
}

module.exports = { HTTP2Server };
