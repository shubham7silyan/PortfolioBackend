module.exports = {
  apps: [{
    name: 'portfolio-backend',
    script: 'index.js',
    instances: 'max', // Use all CPU cores
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'development',
      PORT: 5050
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 5050
    },
    // Performance optimizations
    max_memory_restart: '1G',
    node_args: '--max-old-space-size=1024',
    
    // Monitoring
    monitoring: true,
    pmx: true,
    
    // Logging
    log_file: './logs/combined.log',
    out_file: './logs/out.log',
    error_file: './logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    
    // Auto restart
    watch: false,
    ignore_watch: ['node_modules', 'logs'],
    
    // Graceful shutdown
    kill_timeout: 5000,
    wait_ready: true,
    listen_timeout: 10000
  }]
};
