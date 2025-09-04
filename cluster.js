const { ClusterManager } = require('./middleware/performance');

// Start cluster if this is the entry point
if (ClusterManager.setupCluster()) {
    // Worker process - start the main application
    require('./index.js');
}
