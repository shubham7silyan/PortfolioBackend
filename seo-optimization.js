const express = require('express');
const path = require('path');
const fs = require('fs');

class SEOOptimizer {
    constructor(app) {
        this.app = app;
        this.setupSEORoutes();
    }

    setupSEORoutes() {
        // Dynamic sitemap generation
        this.app.get('/sitemap.xml', (req, res) => {
            const sitemap = this.generateSitemap(req.get('host'));
            res.set('Content-Type', 'application/xml');
            res.send(sitemap);
        });

        // Robots.txt with dynamic sitemap URL
        this.app.get('/robots.txt', (req, res) => {
            const robots = this.generateRobots(req.get('host'));
            res.set('Content-Type', 'text/plain');
            res.send(robots);
        });

        // SEO-friendly redirects
        this.app.get('/portfolio', (req, res) => {
            res.redirect(301, '/#projects-section');
        });

        this.app.get('/about', (req, res) => {
            res.redirect(301, '/#about-section');
        });

        this.app.get('/contact', (req, res) => {
            res.redirect(301, '/#contact-section');
        });

        this.app.get('/skills', (req, res) => {
            res.redirect(301, '/#skills-section');
        });

        // Structured data endpoint
        this.app.get('/structured-data.json', (req, res) => {
            const structuredData = this.generateStructuredData(req.get('host'));
            res.json(structuredData);
        });
    }

    generateSitemap(host) {
        const baseUrl = `https://${host}`;
        const currentDate = new Date().toISOString().split('T')[0];

        return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
    
    <!-- Homepage -->
    <url>
        <loc>${baseUrl}/</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>1.0</priority>
    </url>
    
    <!-- About Section -->
    <url>
        <loc>${baseUrl}/#about-section</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    
    <!-- Skills Section -->
    <url>
        <loc>${baseUrl}/#skills-section</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.7</priority>
    </url>
    
    <!-- Projects Section -->
    <url>
        <loc>${baseUrl}/#projects-section</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.9</priority>
    </url>
    
    <!-- Contact Section -->
    <url>
        <loc>${baseUrl}/#contact-section</loc>
        <lastmod>${currentDate}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.6</priority>
    </url>
    
</urlset>`;
    }

    generateRobots(host) {
        const baseUrl = `https://${host}`;

        return `# Robots.txt for ${host}
User-agent: *
Allow: /

# Sitemap location
Sitemap: ${baseUrl}/sitemap.xml

# Crawl delay for better server performance
Crawl-delay: 1

# Block access to sensitive areas
Disallow: /admin/
Disallow: /api/admin/
Disallow: /*.json$
Disallow: /build/
Disallow: /src/
Disallow: /node_modules/

# Allow important files
Allow: /favicon.ico
Allow: /manifest.json
Allow: /logo192.png
Allow: /logo512.png`;
    }

    generateStructuredData(host) {
        const baseUrl = `https://${host}`;

        return {
            '@context': 'https://schema.org',
            '@graph': [
                {
                    '@type': 'Person',
                    '@id': `${baseUrl}/#person`,
                    'name': 'Shubham Silyan',
                    'jobTitle': 'Full Stack Developer',
                    'description': 'Passionate Full Stack Developer specializing in React.js, Node.js, and MongoDB',
                    'url': baseUrl,
                    'email': 'shubham7silyan@gmail.com',
                    'address': {
                        '@type': 'PostalAddress',
                        'addressLocality': 'Amritsar',
                        'addressRegion': 'Punjab',
                        'addressCountry': 'India'
                    },
                    'knowsAbout': [
                        'React.js', 'Node.js', 'MongoDB', 'JavaScript',
                        'HTML5', 'CSS3', 'Express.js', 'Full Stack Development'
                    ],
                    'sameAs': [
                        'https://github.com/shubhamsilyan',
                        'https://linkedin.com/in/shubhamsilyan',
                        'https://twitter.com/shubhamsilyan'
                    ]
                },
                {
                    '@type': 'WebSite',
                    '@id': `${baseUrl}/#website`,
                    'url': baseUrl,
                    'name': 'Shubham Silyan Portfolio',
                    'description': 'Professional portfolio showcasing full stack development projects and skills',
                    'publisher': {
                        '@id': `${baseUrl}/#person`
                    },
                    'potentialAction': {
                        '@type': 'SearchAction',
                        'target': `${baseUrl}/#projects-section`,
                        'query-input': 'required name=search_term_string'
                    }
                },
                {
                    '@type': 'WebPage',
                    '@id': `${baseUrl}/#webpage`,
                    'url': baseUrl,
                    'name': 'Shubham Silyan - Full Stack Developer',
                    'isPartOf': {
                        '@id': `${baseUrl}/#website`
                    },
                    'about': {
                        '@id': `${baseUrl}/#person`
                    },
                    'description': 'Professional portfolio of Shubham Silyan, a passionate full stack developer from Amritsar, Punjab',
                    'breadcrumb': {
                        '@type': 'BreadcrumbList',
                        'itemListElement': [
                            {
                                '@type': 'ListItem',
                                'position': 1,
                                'name': 'Home',
                                'item': baseUrl
                            },
                            {
                                '@type': 'ListItem',
                                'position': 2,
                                'name': 'About',
                                'item': `${baseUrl}/#about-section`
                            },
                            {
                                '@type': 'ListItem',
                                'position': 3,
                                'name': 'Projects',
                                'item': `${baseUrl}/#projects-section`
                            },
                            {
                                '@type': 'ListItem',
                                'position': 4,
                                'name': 'Contact',
                                'item': `${baseUrl}/#contact-section`
                            }
                        ]
                    }
                }
            ]
        };
    }

    // Generate Open Graph image if needed
    static generateOGImage() {
        // This would typically use a service like Puppeteer to generate OG images
        console.log('📸 OG Image generation - Use a service like og-image.vercel.app');
        return 'https://og-image.vercel.app/Shubham%20Silyan%20-%20Full%20Stack%20Developer.png?theme=dark&md=1&fontSize=100px';
    }
}

module.exports = { SEOOptimizer };
