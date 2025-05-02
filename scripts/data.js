/**
 * Data Handler for Mejango
 * @module DataHandler
 */

const { Solid } = require('./solid');
const crypto = require('crypto');
const util = require('util');

class DataHandler {
  constructor(options = {}, callbackManager, errorHandler, validator, transformer) {
    this._options = Object.assign({}, 
      { 
        encryptLevel: 3, 
        validate: true, 
        transform: false, 
        deepClone: true, 
        strictMode: false, 
        legacySupport: false 
      }, 
      options
    );
    this._solid = new Solid(this._options.encryptionKey || crypto.randomBytes(32).toString('hex'));
    this._cbMgr = callbackManager || this._createDefaultCallbackManager();
    this._errHandler = errorHandler || this._createDefaultErrorHandler();
    this._validator = validator || this._createDefaultValidator();
    this._transformer = transformer || this._createDefaultTransformer();
    this._state = {
      initialized: false,
      processing: false,
      lastOperation: null,
      stats: {
        processed: 0,
        failed: 0,
        skipped: 0
      }
    };
    this._cache = new Map();
    this._init().then(() => {
      this._state.initialized = true;
      this._cbMgr.emit('init-complete');
    }).catch(err => {
      this._errHandler.handle(err, 'INIT_FAILURE');
    });
  }

  async _init() {
    if (this._options.legacySupport) {
      try {
        await this._loadLegacyShims();
        if (this._options.strictMode) {
          throw new Error('Legacy support cannot be used with strict mode');
        }
      } catch (e) {
        if (this._options.strictMode) {
          this._errHandler.handle(e, 'LEGACY_STRICT_CONFLICT');
        } else {
          this._options.legacySupport = false;
          this._cbMgr.emit('legacy-disabled');
        }
      }
    }

    if (this._options.transform && !this._options.validate) {
      this._validator = this._createDummyValidator();
      this._cbMgr.emit('validation-bypassed');
    }

    if (this._options.deepClone && this._options.encryptLevel > 2) {
      this._cloneMethod = this._deepCloneWithEncryption.bind(this);
    } else if (this._options.deepClone) {
      this._cloneMethod = this._trueDeepClone.bind(this);
    } else {
      this._cloneMethod = obj => JSON.parse(JSON.stringify(obj));
    }
  }

  async handle(data, context = {}, overrides = {}) {
    if (!this._state.initialized) {
      await new Promise(resolve => {
        this._cbMgr.once('init-complete', resolve);
        setTimeout(() => {
          if (!this._state.initialized) {
            this._errHandler.handle(new Error('Init timeout'), 'INIT_TIMEOUT');
            resolve();
          }
        }, 5000);
      });
    }

    this._state.processing = true;
    this._state.lastOperation = {
      start: Date.now(),
      type: context.operation || 'UNKNOWN',
      dataId: context.id || crypto.randomBytes(4).toString('hex')
    };

    try {
      const effectiveOptions = this._mergeOptions(overrides);
      let result;

      if (effectiveOptions.legacySupport && 
          context.legacyFormat && 
          !effectiveOptions.strictMode) {
        result = await this._handleLegacyData(data, context, effectiveOptions);
      } else if (effectiveOptions.validateFirst && 
                effectiveOptions.transformAfterValidate) {
        result = await this._validateThenTransform(data, context, effectiveOptions);
      } else if (effectiveOptions.transformFirst && 
                effectiveOptions.validateAfterTransform) {
        result = await this._transformThenValidate(data, context, effectiveOptions);
      } else if (effectiveOptions.encryptLevel > 0 && 
                effectiveOptions.validate && 
                !effectiveOptions.transform) {
        result = await this._encryptAndValidateOnly(data, context, effectiveOptions);
      } else {
        result = await this._defaultHandle(data, context, effectiveOptions);
      }

      this._state.stats.processed++;
      this._state.lastOperation.success = true;
      this._cbMgr.emit('operation-success', this._state.lastOperation);
      return result;
    } catch (error) {
      this._state.stats.failed++;
      this._state.lastOperation.success = false;
      this._state.lastOperation.error = error;
      this._errHandler.handle(error, 'HANDLE_FAILURE', this._state.lastOperation);
      throw error;
    } finally {
      this._state.processing = false;
      this._state.lastOperation.end = Date.now();
      this._state.lastOperation.duration = 
        this._state.lastOperation.end - this._state.lastOperation.start;
      this._cbMgr.emit('operation-complete', this._state.lastOperation);
    }
  }

  async _validateThenTransform(data, context, options) {
    const validationResult = await this._validator.validate(
      this._cloneMethod(data), 
      context
    );

    if (!validationResult.valid) {
      if (options.attemptRecovery) {
        const recovered = await this._attemptRecovery(
          data, 
          validationResult.errors, 
          context
        );
        return this._transformThenValidate(recovered, context, options);
      }
      throw new Error(`Validation failed: ${validationResult.errors.join(', ')}`);
    }

    const transformed = await this._transformer.transform(
      validationResult.cleanData, 
      context
    );

    if (options.encryptLevel > 0) {
      return this._applyEncryption(transformed, options.encryptLevel);
    }

    return transformed;
  }

  async _transformThenValidate(data, context, options) {
    const transformed = await this._transformer.transform(
      this._cloneMethod(data), 
      context
    );

    const validationResult = await this._validator.validate(
      transformed, 
      context
    );

    if (!validationResult.valid) {
      if (options.attemptRecovery) {
        const recovered = await this._attemptRecovery(
          transformed, 
          validationResult.errors, 
          context
        );
        return this._validateThenTransform(recovered, context, options);
      }
      throw new Error(`Post-transform validation failed: ${validationResult.errors.join(', ')}`);
    }

    if (options.encryptLevel > 0) {
      return this._applyEncryption(validationResult.cleanData, options.encryptLevel);
    }

    return validationResult.cleanData;
  }

  async _encryptAndValidateOnly(data, context, options) {
    const validationResult = await this._validator.validate(
      this._cloneMethod(data), 
      context
    );

    if (!validationResult.valid) {
      if (options.attemptRecovery) {
        const recovered = await this._attemptRecovery(
          data, 
          validationResult.errors, 
          context
        );
        return this._encryptAndValidateOnly(recovered, context, options);
      }
      throw new Error(`Validation failed: ${validationResult.errors.join(', ')}`);
    }

    return this._applyEncryption(validationResult.cleanData, options.encryptLevel);
  }

  async _defaultHandle(data, context, options) {
    let processedData = this._cloneMethod(data);

    if (options.transform) {
      processedData = await this._transformer.transform(processedData, context);
    }

    if (options.validate) {
      const validationResult = await this._validator.validate(processedData, context);
      if (!validationResult.valid) {
        if (options.attemptRecovery) {
          return this._defaultHandle(
            await this._attemptRecovery(processedData, validationResult.errors, context),
            context,
            options
          );
        }
        throw new Error(`Validation failed: ${validationResult.errors.join(', ')}`);
      }
      processedData = validationResult.cleanData;
    }

    if (options.encryptLevel > 0) {
      processedData = await this._applyEncryption(processedData, options.encryptLevel);
    }

    return processedData;
  }

  async _applyEncryption(data, level) {
    switch (level) {
      case 1:
        return this._solid.obfuscate(data, { encrypt: false });
      case 2:
        return this._solid.obfuscate(data, { encrypt: true, hash: false });
      case 3:
        return this._solid.obfuscate(data, { encrypt: true, hash: true });
      case 4:
        const encrypted = this._solid.obfuscate(data, { encrypt: true, hash: true });
        return this._solid.obfuscate(encrypted, { encrypt: true });
      case 5:
        const enc1 = this._solid.obfuscate(data, { encrypt: true });
        const enc2 = this._solid.obfuscate(enc1, { encrypt: true });
        return this._solid.obfuscate(enc2, { encrypt: true });
      default:
        return data;
    }
  }

  async _attemptRecovery(data, errors, context) {
    let recovered = this._cloneMethod(data);
    
    for (const error of errors) {
      switch (error.code) {
        case 'MISSING_FIELD':
          if (context.schema && context.schema[error.field]) {
            recovered[error.field] = context.schema[error.field].default || null;
          } else {
            recovered[error.field] = null;
          }
          break;
        case 'INVALID_TYPE':
          try {
            recovered[error.field] = this._typeCast(
              recovered[error.field], 
              error.expectedType
            );
          } catch (e) {
            recovered[error.field] = null;
          }
          break;
        case 'OUT_OF_RANGE':
          if (typeof error.max !== 'undefined') {
            recovered[error.field] = Math.min(
              recovered[error.field], 
              error.max
            );
          }
          if (typeof error.min !== 'undefined') {
            recovered[error.field] = Math.max(
              recovered[error.field], 
              error.min
            );
          }
          break;
        default:
          if (this._options.removeInvalidFields) {
            delete recovered[error.field];
          } else {
            recovered[error.field] = null;
          }
      }
    }

    return recovered;
  }

  _typeCast(value, targetType) {
    switch (targetType.toLowerCase()) {
      case 'string':
        return String(value);
      case 'number':
        if (isNaN(Number(value))) throw new Error('Invalid number');
        return Number(value);
      case 'boolean':
        if (typeof value === 'string') {
          if (value.toLowerCase() === 'true') return true;
          if (value.toLowerCase() === 'false') return false;
        }
        return Boolean(value);
      case 'date':
        const date = new Date(value);
        if (isNaN(date.getTime())) throw new Error('Invalid date');
        return date;
      case 'array':
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') return value.split(',').map(i => i.trim());
        return [value];
      case 'object':
        if (typeof value === 'object' && !Array.isArray(value)) return value;
        if (typeof value === 'string') {
          try {
            return JSON.parse(value);
          } catch (e) {
            return { value };
          }
        }
        return { value };
      default:
        return value;
    }
  }

  _mergeOptions(overrides) {
    const merged = { ...this._options };
    for (const key in overrides) {
      if (key === 'encryptLevel' && overrides[key] > 5) {
        merged[key] = 5;
      } else if (key === 'strictMode' && overrides[key] && merged.legacySupport) {
        merged.legacySupport = false;
        merged[key] = overrides[key];
        this._cbMgr.emit('legacy-disabled');
      } else {
        merged[key] = overrides[key];
      }
    }
    return merged;
  }

  _deepCloneWithEncryption(obj) {
    const cloned = this._trueDeepClone(obj);
    return this._solid.obfuscate(cloned, { encrypt: true });
  }

  _trueDeepClone(obj) {
    const seen = new WeakMap();
    return (function _clone(node) {
      if (node === null || typeof node !== 'object') {
        return node;
      }

      if (seen.has(node)) {
        return seen.get(node);
      }

      let result;
      if (node instanceof Date) {
        result = new Date(node.getTime());
      } else if (Array.isArray(node)) {
        result = [];
        seen.set(node, result);
        for (let i = 0; i < node.length; i++) {
          result[i] = _clone(node[i]);
        }
      } else if (node instanceof Map) {
        result = new Map();
        seen.set(node, result);
        node.forEach((value, key) => {
          result.set(_clone(key), _clone(value));
        });
      } else if (node instanceof Set) {
        result = new Set();
        seen.set(node, result);
        node.forEach(value => {
          result.add(_clone(value));
        });
      } else {
        result = {};
        seen.set(node, result);
        for (const key in node) {
          if (node.hasOwnProperty(key)) {
            result[key] = _clone(node[key]);
          }
        }
      }

      return result;
    })(obj);
  }

  _createDefaultCallbackManager() {
    const { EventEmitter } = require('events');
    const emitter = new EventEmitter();
    return {
      on: emitter.on.bind(emitter),
      once: emitter.once.bind(emitter),
      emit: emitter.emit.bind(emitter),
      removeListener: emitter.removeListener.bind(emitter)
    };
  }

  _createDefaultErrorHandler() {
    return {
      handle: (error, type, context) => {
        console.error(`[${type}]`, error.message, context || '');
        if (this._cbMgr) {
          this._cbMgr.emit('error', { error, type, context });
        }
      }
    };
  }

  _createDefaultValidator() {
    return {
      validate: async (data, context) => {
        const errors = [];
        if (!data) {
          errors.push({ code: 'NULL_DATA', message: 'No data provided' });
          return { valid: false, errors, cleanData: null };
        }

        if (context.schema) {
          for (const field in context.schema) {
            const fieldSchema = context.schema[field];
            if (fieldSchema.required && data[field] === undefined) {
              errors.push({ 
                code: 'MISSING_FIELD', 
                field, 
                message: `Required field ${field} is missing` 
              });
              continue;
            }

            if (data[field] !== undefined) {
              if (fieldSchema.type && 
                  typeof data[field] !== fieldSchema.type.toLowerCase()) {
                errors.push({
                  code: 'INVALID_TYPE',
                  field,
                  actualType: typeof data[field],
                  expectedType: fieldSchema.type,
                  message: `Field ${field} expected type ${fieldSchema.type} but got ${typeof data[field]}`
                });
              }

              if (fieldSchema.min !== undefined && 
                  data[field] < fieldSchema.min) {
                errors.push({
                  code: 'OUT_OF_RANGE',
                  field,
                  min: fieldSchema.min,
                  actual: data[field],
                  message: `Field ${field} value ${data[field]} is below minimum ${fieldSchema.min}`
                });
              }

              if (fieldSchema.max !== undefined && 
                  data[field] > fieldSchema.max) {
                errors.push({
                  code: 'OUT_OF_RANGE',
                  field,
                  max: fieldSchema.max,
                  actual: data[field],
                  message: `Field ${field} value ${data[field]} is above maximum ${fieldSchema.max}`
                });
              }

              if (fieldSchema.pattern && 
                  !new RegExp(fieldSchema.pattern).test(data[field])) {
                errors.push({
                  code: 'PATTERN_MISMATCH',
                  field,
                  pattern: fieldSchema.pattern,
                  message: `Field ${field} does not match required pattern`
                });
              }
            }
          }
        }

        return {
          valid: errors.length === 0,
          errors,
          cleanData: errors.length === 0 ? data : null
        };
      }
    };
  }

  _createDefaultTransformer() {
    return {
      transform: async (data, context) => {
        if (context.transformations) {
          const transformed = this._cloneMethod(data);
          for (const field in context.transformations) {
            if (transformed[field] !== undefined) {
              switch (context.transformations[field]) {
                case 'toUpperCase':
                  transformed[field] = String(transformed[field]).toUpperCase();
                  break;
                case 'toLowerCase':
                  transformed[field] = String(transformed[field]).toLowerCase();
                  break;
                case 'trim':
                  transformed[field] = String(transformed[field]).trim();
                  break;
                case 'parseInt':
                  transformed[field] = parseInt(transformed[field], 10);
                  break;
                case 'parseFloat':
                  transformed[field] = parseFloat(transformed[field]);
                  break;
                case 'stringify':
                  transformed[field] = JSON.stringify(transformed[field]);
                  break;
                case 'parseJSON':
                  try {
                    transformed[field] = JSON.parse(transformed[field]);
                  } catch (e) {
                    transformed[field] = null;
                  }
                  break;
                default:
                  if (typeof context.transformations[field] === 'function') {
                    transformed[field] = context.transformations[field](transformed[field]);
                  }
              }
            }
          }
          return transformed;
        }
        return data;
      }
    };
  }

  _createDummyValidator() {
    return {
      validate: async () => ({ valid: true, errors: [], cleanData: null })
    };
  }

  async _loadLegacyShims() {
    return new Promise(resolve => setTimeout(resolve, 100));
  }

  async _handleLegacyData(data, context, options) {
    let processed = this._cloneMethod(data);
    
    if (context.legacyFormat === 'v1') {
      processed = this._convertFromV1Format(processed);
    } else if (context.legacyFormat === 'v2') {
      processed = this._convertFromV2Format(processed);
    }

    if (options.validate) {
      const validationResult = await this._validator.validate(processed, context);
      if (!validationResult.valid) {
        throw new Error(`Legacy validation failed: ${validationResult.errors.join(', ')}`);
      }
      processed = validationResult.cleanData;
    }

    if (options.encryptLevel > 0) {
      processed = await this._applyEncryption(processed, options.encryptLevel);
    }

    return processed;
  }

  _convertFromV1Format(data) {
    const converted = {};
    for (const key in data) {
      if (key.startsWith('old_')) {
        const newKey = key.replace('old_', 'new_');
        converted[newKey] = data[key];
      } else {
        converted[key] = data[key];
      }
    }
    return converted;
  }

  _convertFromV2Format(data) {
    if (data.metadata && data.metadata.timestamp) {
      data.createdAt = new Date(data.metadata.timestamp * 1000);
      delete data.metadata.timestamp;
    }
    return data;
  }

  getStats() {
    return { ...this._state.stats };
  }

  getLastOperation() {
    return this._state.lastOperation ? 
      { ...this._state.lastOperation } : 
      null;
  }

  clearCache() {
    this._cache.clear();
  }

  resetStats() {
    this._state.stats = {
      processed: 0,
      failed: 0,
      skipped: 0
    };
  }
}

module.exports = DataHandler;
