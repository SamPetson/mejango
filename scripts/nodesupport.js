/**
 * NodeSupport - Node.js Integration Layer for Mejango
 * @module NodeSupport
 */

const cluster = require('cluster');
const os = require('os');
const { EventEmitter } = require('events');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { Solid } = require('./solid');
const { DataHandler } = require('./data');
const { MejangoCollection } = require('./mejango');

class NodeSupport extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      clusterMode: false,
      workerCount: os.cpus().length,
      persistence: true,
      encryptionLevel: 2,
      maxMemoryUsage: 0.8, // 80% of available memory
      ...options
    };
    
    this._collections = new Map();
    this._workerPool = new Map();
    this._isMaster = cluster.isMaster;
    this._shutdownInProgress = false;
    this._healthCheckInterval = null;
    this._resourceMonitorInterval = null;
    this._backupInterval = null;
    
    // Initialize core components
    this._solid = new Solid(this.options.encryptionKey || this._generateClusterKey());
    this._dataHandler = new DataHandler({
      encryptLevel: this.options.encryptionLevel
    }, this._createEnhancedCallbackManager());
    
    // Bind error handlers
    process.on('uncaughtException', this._handleProcessError.bind(this));
    process.on('unhandledRejection', this._handleProcessError.bind(this));
    process.on('SIGTERM', this._gracefulShutdown.bind(this));
    process.on('SIGINT', this._gracefulShutdown.bind(this));
    
    // Initialize based on cluster mode
    if (this.options.clusterMode && this._isMaster) {
      this._initCluster();
    } else {
      this._initSingleProcess();
    }
  }

  /*****************************
   * INITIALIZATION METHODS
   *****************************/

  async _initCluster() {
    this.emit('cluster-init-start');
    
    // Fork workers
    for (let i = 0; i < this.options.workerCount; i++) {
      const worker = cluster.fork({
        WORKER_ID: i + 1,
        CLUSTER_MODE: true,
        ENCRYPTION_KEY: this.options.encryptionKey
      });
      
      this._workerPool.set(worker.id, {
        id: worker.id,
        process: worker,
        status: 'starting',
        lastHealthCheck: Date.now(),
        load: 0
      });
      
      worker.on('message', this._handleWorkerMessage.bind(this, worker));
      worker.on('exit', this._handleWorkerExit.bind(this, worker));
    }
    
    // Initialize health monitoring
    this._startHealthMonitoring();
    this._startResourceMonitoring();
    
    if (this.options.persistence) {
      this._startBackupCycle();
    }
    
    this.emit('cluster-init-complete');
  }

  async _initSingleProcess() {
    this.emit('single-process-init-start');
    
    // Initialize health monitoring
    this._startHealthMonitoring();
    this._startResourceMonitoring();
    
    if (this.options.persistence) {
      this._startBackupCycle();
    }
    
    // Load any existing collections if in persistence mode
    if (this.options.persistence) {
      try {
        await this._loadPersistedCollections();
      } catch (err) {
        this.emit('persistence-load-error', err);
      }
    }
    
    this.emit('single-process-init-complete');
  }

  /*****************************
   * CORE FUNCTIONALITY
   *****************************/

  async createCollection(name, schema = {}, collectionOptions = {}) {
    if (this._collections.has(name)) {
      throw new Error(`Collection ${name} already exists`);
    }
    
    const options = {
      autoObfuscate: true,
      schema,
      ...collectionOptions
    };
    
    const collection = new MejangoCollection(
      name,
      this.options.persistence ? this._getDataPath() : ':memory:',
      options
    );
    
    this._collections.set(name, {
      instance: collection,
      schema,
      stats: {
        operations: 0,
        lastOperation: null
      }
    });
    
    if (this.options.persistence) {
      await this._persistCollectionConfig(name);
    }
    
    return collection;
  }

  async getCollection(name) {
    if (!this._collections.has(name)) {
      if (this.options.autoCreateCollections) {
        return this.createCollection(name);
      }
      throw new Error(`Collection ${name} does not exist`);
    }
    
    return this._collections.get(name).instance;
  }

  async distributedOperation(operationName, ...args) {
    if (!this.options.clusterMode || !this._isMaster) {
      return this._executeLocalOperation(operationName, ...args);
    }
    
    // Select the least busy worker
    const worker = this._selectWorker();
    
    return new Promise((resolve, reject) => {
      const operationId = crypto.randomBytes(8).toString('hex');
      
      const timeout = setTimeout(() => {
        this._cleanupOperationListeners(operationId);
        reject(new Error(`Operation ${operationName} timed out`));
      }, this.options.operationTimeout || 30000);
      
      const messageHandler = (msg) => {
        if (msg.operationId === operationId) {
          clearTimeout(timeout);
          this._cleanupOperationListeners(operationId);
          
          if (msg.error) {
            reject(new Error(msg.error));
          } else {
            resolve(msg.result);
          }
        }
      };
      
      worker.process.on('message', messageHandler);
      
      // Store listener for cleanup
      this._operationListeners = this._operationListeners || new Map();
      this._operationListeners.set(operationId, { worker, handler: messageHandler });
      
      // Send operation to worker
      worker.process.send({
        type: 'operation',
        operationId,
        operationName,
        args
      });
    });
  }

  /*****************************
   * PERSISTENCE METHODS
   *****************************/

  async _loadPersistedCollections() {
    const dataPath = this._getDataPath();
    
    try {
      await fs.access(dataPath);
      const files = await fs.readdir(dataPath);
      
      const collectionConfigs = files.filter(f => f.endsWith('.config.json'));
      
      for (const configFile of collectionConfigs) {
        try {
          const configData = await fs.readFile(path.join(dataPath, configFile), 'utf8');
          const config = JSON.parse(configData);
          
          const collection = new MejangoCollection(
            config.name,
            dataPath,
            config.options
          );
          
          this._collections.set(config.name, {
            instance: collection,
            schema: config.schema,
            stats: {
              operations: 0,
              lastOperation: null
            }
          });
          
          this.emit('collection-loaded', config.name);
        } catch (err) {
          this.emit('collection-load-error', {
            file: configFile,
            error: err.message
          });
        }
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        throw err;
      }
      // Data directory doesn't exist, will be created on first persist
    }
  }

  async _persistCollectionConfig(collectionName) {
    if (!this.options.persistence) return;
    
    const collection = this._collections.get(collectionName);
    if (!collection) return;
    
    const dataPath = this._getDataPath();
    
    try {
      await fs.mkdir(dataPath, { recursive: true });
      
      const config = {
        name: collectionName,
        schema: collection.schema,
        options: {
          autoObfuscate: true,
          ...collection.instance.options
        }
      };
      
      await fs.writeFile(
        path.join(dataPath, `${collectionName}.config.json`),
        JSON.stringify(config, null, 2),
        'utf8'
      );
    } catch (err) {
      this.emit('persistence-error', {
        collection: collectionName,
        error: err.message
      });
    }
  }

  async _startBackupCycle() {
    if (this._backupInterval) clearInterval(this._backupInterval);
    
    const backupInterval = this.options.backupInterval || 3600000; // 1 hour default
    
    this._backupInterval = setInterval(async () => {
      this.emit('backup-start');
      
      try {
        if (this.options.clusterMode && this._isMaster) {
          // In cluster mode, pause workers before backup
          await this._pauseWorkers();
        }
        
        await this._createBackup();
        
        if (this.options.clusterMode && this._isMaster) {
          // Resume workers after backup
          await this._resumeWorkers();
        }
        
        this.emit('backup-complete');
      } catch (err) {
        this.emit('backup-error', err);
      }
    }, backupInterval);
    
    // Run first backup immediately
    setTimeout(() => {
      this.emit('backup-scheduled');
    }, 1000);
  }

  /*****************************
   * CLUSTER MANAGEMENT
   *****************************/

  _selectWorker() {
    let selectedWorker = null;
    let lowestLoad = Infinity;
    
    for (const [_, worker] of this._workerPool) {
      if (worker.status === 'ready' && worker.load < lowestLoad) {
        lowestLoad = worker.load;
        selectedWorker = worker;
      }
    }
    
    if (!selectedWorker) {
      throw new Error('No available workers');
    }
    
    return selectedWorker;
  }

  async _pauseWorkers() {
    if (!this.options.clusterMode || !this._isMaster) return;
    
    this.emit('workers-pausing');
    
    const pausePromises = [];
    
    for (const [_, worker] of this._workerPool) {
      if (worker.status === 'ready') {
        pausePromises.push(new Promise(resolve => {
          const timeout = setTimeout(() => {
            worker.process.removeListener('message', messageHandler);
            resolve(false);
          }, 5000);
          
          const messageHandler = (msg) => {
            if (msg.type === 'paused') {
              clearTimeout(timeout);
              worker.status = 'paused';
              resolve(true);
            }
          };
          
          worker.process.on('message', messageHandler);
          worker.process.send({ type: 'pause' });
        }));
      }
    }
    
    const results = await Promise.all(pausePromises);
    this.emit('workers-paused', {
      successCount: results.filter(r => r).length,
      total: results.length
    });
  }

  async _resumeWorkers() {
    if (!this.options.clusterMode || !this._isMaster) return;
    
    this.emit('workers-resuming');
    
    for (const [_, worker] of this._workerPool) {
      if (worker.status === 'paused') {
        worker.process.send({ type: 'resume' });
        worker.status = 'ready';
      }
    }
    
    this.emit('workers-resumed');
  }

  _handleWorkerMessage(worker, message) {
    if (message.type === 'status-update') {
      const workerData = this._workerPool.get(worker.id);
      if (workerData) {
        workerData.status = message.status;
        workerData.load = message.load || 0;
        workerData.lastHealthCheck = Date.now();
      }
    } else if (message.type === 'operation-result') {
      // Handled in distributedOperation
    } else if (message.type === 'error') {
      this.emit('worker-error', {
        workerId: worker.id,
        error: message.error
      });
    }
  }

  _handleWorkerExit(worker, code, signal) {
    const workerData = this._workerPool.get(worker.id);
    if (workerData) {
      this._workerPool.delete(worker.id);
      this.emit('worker-exited', {
        workerId: worker.id,
        code,
        signal,
        wasIntentional: this._shutdownInProgress
      });
    }
    
    if (!this._shutdownInProgress && this.options.clusterMode && this._isMaster) {
      // Restart the worker if this wasn't part of a shutdown
      setTimeout(() => {
        this.emit('worker-restarting', worker.id);
        const newWorker = cluster.fork({
          WORKER_ID: worker.id,
          CLUSTER_MODE: true,
          ENCRYPTION_KEY: this.options.encryptionKey
        });
        
        this._workerPool.set(newWorker.id, {
          id: newWorker.id,
          process: newWorker,
          status: 'starting',
          lastHealthCheck: Date.now(),
          load: 0
        });
        
        newWorker.on('message', this._handleWorkerMessage.bind(this, newWorker));
        newWorker.on('exit', this._handleWorkerExit.bind(this, newWorker));
      }, 1000);
    }
  }

  /*****************************
   * HEALTH MONITORING
   *****************************/

  _startHealthMonitoring() {
    if (this._healthCheckInterval) clearInterval(this._healthCheckInterval);
    
    this._healthCheckInterval = setInterval(() => {
      if (this.options.clusterMode && this._isMaster) {
        this._checkWorkerHealth();
      }
      this._checkMemoryUsage();
    }, this.options.healthCheckInterval || 10000);
  }

  _checkWorkerHealth() {
    const now = Date.now();
    const timeout = this.options.workerTimeout || 30000;
    
    for (const [_, worker] of this._workerPool) {
      if (worker.status !== 'starting' && now - worker.lastHealthCheck > timeout) {
        this.emit('worker-unresponsive', {
          workerId: worker.id,
          lastHealthCheck: worker.lastHealthCheck
        });
        
        // Forcefully terminate the worker
        worker.process.kill('SIGTERM');
        this._workerPool.delete(worker.id);
      }
    }
  }

  _checkMemoryUsage() {
    const memoryUsage = process.memoryUsage();
    const maxMemory = this.options.maxMemoryUsage * os.totalmem();
    
    if (memoryUsage.rss > maxMemory) {
      this.emit('memory-pressure', {
        rss: memoryUsage.rss,
        heapTotal: memoryUsage.heapTotal,
        heapUsed: memoryUsage.heapUsed,
        external: memoryUsage.external,
        maxMemory
      });
      
      if (this.options.clusterMode && this._isMaster) {
        // In cluster mode, redistribute load when memory is high
        this._redistributeLoad();
      } else {
        // In single process, try to GC and clear caches
        if (global.gc) {
          global.gc();
        }
        
        // Clear some caches
        this._dataHandler.clearCache();
        for (const [_, collection] of this._collections) {
          if (collection.instance.clearCache) {
            collection.instance.clearCache();
          }
        }
      }
    }
  }

  _startResourceMonitoring() {
    if (this._resourceMonitorInterval) clearInterval(this._resourceMonitorInterval);
    
    this._resourceMonitorInterval = setInterval(() => {
      const memoryUsage = process.memoryUsage();
      const cpuUsage = process.cpuUsage();
      const loadAvg = os.loadavg();
      
      this.emit('resource-metrics', {
        memory: {
          rss: memoryUsage.rss,
          heapTotal: memoryUsage.heapTotal,
          heapUsed: memoryUsage.heapUsed,
          external: memoryUsage.external
        },
        cpu: {
          user: cpuUsage.user,
          system: cpuUsage.system
        },
        load: {
          avg1: loadAvg[0],
          avg5: loadAvg[1],
          avg15: loadAvg[2]
        }
      });
    }, this.options.resourceMonitorInterval || 5000);
  }

  /*****************************
   * UTILITY METHODS
   *****************************/

  _generateClusterKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  _getDataPath() {
    return path.join(
      this.options.dataDirectory || path.join(process.cwd(), 'mejango_data'),
      'collections'
    );
  }

  _createEnhancedCallbackManager() {
    const callbacks = new Map();
    
    return {
      register: (event, callback) => {
        const id = crypto.randomBytes(4).toString('hex');
        callbacks.set(id, { event, callback });
        return id;
      },
      unregister: (id) => {
        callbacks.delete(id);
      },
      emit: (event, data) => {
        this.emit(event, data);
        
        for (const [_, cb] of callbacks) {
          if (cb.event === event) {
            try {
              cb.callback(data);
            } catch (err) {
              this.emit('callback-error', {
                event,
                error: err.message
              });
            }
          }
        }
      }
    };
  }

  _handleProcessError(error, origin) {
    this.emit('process-error', {
      error: error.message,
      stack: error.stack,
      origin
    });
    
    if (!this._shutdownInProgress) {
      this._gracefulShutdown();
    }
  }

  async _gracefulShutdown() {
    if (this._shutdownInProgress) return;
    this._shutdownInProgress = true;
    
    this.emit('shutdown-start');
    
    // Clear intervals
    if (this._healthCheckInterval) clearInterval(this._healthCheckInterval);
    if (this._resourceMonitorInterval) clearInterval(this._resourceMonitorInterval);
    if (this._backupInterval) clearInterval(this._backupInterval);
    
    // Persist any pending data
    if (this.options.persistence) {
      try {
        await this._createBackup();
      } catch (err) {
        this.emit('shutdown-backup-error', err);
      }
    }
    
    // In cluster mode, terminate workers
    if (this.options.clusterMode && this._isMaster) {
      const workerExitPromises = [];
      
      for (const [_, worker] of this._workerPool) {
        workerExitPromises.push(new Promise(resolve => {
          worker.process.on('exit', resolve);
          worker.process.kill('SIGTERM');
        }));
      }
      
      await Promise.all(workerExitPromises);
    }
    
    // Close all collections
    for (const [name, collection] of this._collections) {
      try {
        if (typeof collection.instance.close === 'function') {
          await collection.instance.close();
        }
      } catch (err) {
        this.emit('collection-close-error', {
          collection: name,
          error: err.message
        });
      }
    }
    
    this.emit('shutdown-complete');
    
    // Exit the process
    setTimeout(() => {
      process.exit(0);
    }, 100);
  }

  async _executeLocalOperation(operationName, ...args) {
    const [collectionName, ...operationArgs] = args;
    
    try {
      const collection = await this.getCollection(collectionName);
      
      if (!collection[operationName]) {
        throw new Error(`Operation ${operationName} not supported`);
      }
      
      const result = await collection[operationName](...operationArgs);
      
      // Update collection stats
      const collectionData = this._collections.get(collectionName);
      if (collectionData) {
        collectionData.stats.operations++;
        collectionData.stats.lastOperation = {
          name: operationName,
          timestamp: new Date()
        };
      }
      
      return result;
    } catch (err) {
      this.emit('operation-error', {
        operation: operationName,
        collection: collectionName,
        error: err.message
      });
      throw err;
    }
  }

  _cleanupOperationListeners(operationId) {
    if (!this._operationListeners || !this._operationListeners.has(operationId)) {
      return;
    }
    
    const { worker, handler } = this._operationListeners.get(operationId);
    worker.process.removeListener('message', handler);
    this._operationListeners.delete(operationId);
  }

  _redistributeLoad() {
    this.emit('load-redistribution-start');
    setTimeout(() => {
      this.emit('load-redistribution-complete');
    }, 1000);
  }

  async _createBackup() {
    if (!this.options.persistence) return;
    
    const backupPath = path.join(
      this.options.dataDirectory || path.join(process.cwd(), 'mejango_data'),
      'backups',
      `backup_${new Date().toISOString().replace(/[:.]/g, '-')}`
    );
    
    try {
      await fs.mkdir(backupPath, { recursive: true });
      
      // Backup collection data
      for (const [name] of this._collections) {
        const sourceFile = path.join(this._getDataPath(), `${name}.mjn`);
        const backupFile = path.join(backupPath, `${name}.mjn`);
        
        try {
          await fs.copyFile(sourceFile, backupFile);
        } catch (err) {
          if (err.code !== 'ENOENT') {
            throw err;
          }
          // File doesn't exist, skip
        }
      }
      
      // Backup collection configs
      for (const [name, collection] of this._collections) {
        const config = {
          name,
          schema: collection.schema,
          options: collection.instance.options
        };
        
        await fs.writeFile(
          path.join(backupPath, `${name}.config.json`),
          JSON.stringify(config, null, 2),
          'utf8'
        );
      }
      
      return backupPath;
    } catch (err) {
      throw new Error(`Backup failed: ${err.message}`);
    }
  }
}

// Worker process implementation
if (cluster.isWorker) {
  const workerId = parseInt(process.env.WORKER_ID, 10);
  const encryptionKey = process.env.ENCRYPTION_KEY;
  
  const nodeSupport = new NodeSupport({
    clusterMode: true,
    isWorker: true,
    encryptionKey,
    persistence: true
  });
  
  // Worker message handler
  process.on('message', async (message) => {
    if (message.type === 'operation') {
      try {
        const result = await nodeSupport._executeLocalOperation(
          message.operationName,
          ...message.args
        );
        
        process.send({
          type: 'operation-result',
          operationId: message.operationId,
          result
        });
      } catch (error) {
        process.send({
          type: 'operation-result',
          operationId: message.operationId,
          error: error.message
        });
      }
    } else if (message.type === 'pause') {
      // Pause operation processing
      process.send({ type: 'paused' });
    } else if (message.type === 'resume') {
      // Resume operation processing
      process.send({ type: 'resumed' });
    }
  });
  
  // Regular health updates
  setInterval(() => {
    const memoryUsage = process.memoryUsage();
    
    process.send({
      type: 'status-update',
      status: 'ready',
      load: memoryUsage.heapUsed / memoryUsage.heapTotal,
      workerId
    });
  }, 5000);
}

module.exports = NodeSupport;
