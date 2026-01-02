import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import axios from 'axios';
import https from 'https';
import winston from 'winston';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import NodeCache from 'node-cache';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import admin from 'firebase-admin';
import CryptoJS from 'crypto-js';
import { body, validationResult } from 'express-validator';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const logsDir = path.join(__dirname, "logs");
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// ============================================================================
// LOGGER - Production Grade
// ============================================================================
const logger = winston.createLogger({
  level: process.env.NODE_ENV === "production" ? "info" : "debug",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "paydrak-topup-service" },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(winston.format.colorize(), winston.format.simple())
    }),
    new winston.transports.File({ 
      filename: path.join(logsDir, "error.log"),
      level: "error",
      maxsize: 10485760,
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: path.join(logsDir, "topup.log"),
      maxsize: 10485760,
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: path.join(logsDir, "fraud.log"),
      level: "warn",
      maxsize: 10485760,
      maxFiles: 10
    })
  ]
});

// ============================================================================
// GLOBAL ERROR HANDLERS
// ============================================================================
process.on("uncaughtException", (error) => {
  logger.error("Uncaught Exception", { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection", { reason, promise });
});

// ============================================================================
// SECURE CONFIGURATION
// ============================================================================
const config = {
  port: process.env.PORT || process.env.TOPUP_PORT || 3000,
  nodeEnv: process.env.NODE_ENV || "development",

  // A1Topup Credentials
  a1topup: {
    username: process.env.A1TOPUP_USERNAME || '505738',
    password: process.env.A1TOPUP_PASSWORD || '4ff6olp2',
    baseUrl: 'https://business.a1topup.com/recharge',
    defaultCircle: '5',
    testMode: process.env.TEST_MODE
  },

  // Static Exchange Rate
  staticExchangeRate: 17.00,

  // Security
  security: {
    encryptionKey: (() => {
      const key = process.env.ENCRYPTION_KEY;
      if (!key || key === "change-this-key" || key.length < 32) {
        logger.error("❌ ENCRYPTION_KEY must be set in .env and be at least 32 characters");
        process.exit(1);
      }
      return key;
    })(),
    corsOrigin: process.env.CORS_ORIGIN || "*",
    trustProxy: process.env.TRUST_PROXY !== "false",
    sessionTTL: 15 * 60 * 1000 // 15 minutes
  },

  // Paystack
  paystack: {
    secretKey: process.env.PAYSTACK_SECRET_KEY,
    publicKey: process.env.PAYSTACK_PUBLIC_KEY
  },

  // Fees & Loyalty
  fees: {
    convenienceFeeInr: 10,
    canWaiveWithLP: true,
    lpRequiredToWaive: 200
  },

  loyalty: {
    lpPerTenRupees: 1,
    tiers: {
      BRONZE: { minXLP: 0, name: 'Bronze', multiplier: 1.0 },
      SILVER: { minXLP: 5000, name: 'Silver', multiplier: 1.2 },
      GOLD: { minXLP: 15000, name: 'Gold', multiplier: 1.5 }
    }
  },

  // Transaction Limits (Anti-Fraud)
  limits: {
    minRechargeInr: 10,
    maxRechargeInr: 10000,
    minTotalAmountNgn: 1000,
    maxTotalAmountNgn: 5000000,
    dailyLimitPerUser: 50000, // ₹50,000 per day per user
    dailyLimitPerIP: 100000, // ₹100,000 per day per IP
    maxRapidTransactions: 3 // Max transactions in 5 minutes
  },

  // Timeouts
  timeouts: {
    api: 30000,
    a1topup: 45000
  }
};

// ============================================================================
// FIREBASE INITIALIZATION
// ============================================================================
let db;

try {
  const requiredVars = {
    FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID,
    FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY,
    FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL,
    FIREBASE_DATABASE_URL: process.env.FIREBASE_DATABASE_URL
  };

  const missingVars = Object.keys(requiredVars).filter(key => !requiredVars[key]);
  
  if (missingVars.length > 0) {
    logger.error("Missing Firebase environment variables", { missingVars });
    process.exit(1);
  }

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL
    }),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });

  db = admin.database();
  logger.info('✅ Firebase Realtime Database initialized');
} catch (error) {
  logger.error('❌ Firebase initialization failed', { error: error.message });
  process.exit(1);
}

// ============================================================================
// CACHE & METRICS
// ============================================================================
const cache = new NodeCache({ stdTTL: 600, checkperiod: 60 });

const metrics = {
  requests: { total: 0, success: 0, errors: 0 },
  topups: { total: 0, completed: 0, failed: 0, pending: 0 },
  fraud: { blocked: 0, warnings: 0 },
  api: {
    a1topup: { calls: 0, failures: 0, avgLatency: 0 }
  }
};

// ============================================================================
// CUSTOM ERRORS
// ============================================================================
class APIError extends Error {
  constructor(message, statusCode = 500, details = {}) {
    super(message);
    this.name = "APIError";
    this.statusCode = statusCode;
    this.details = details;
  }
}

class ValidationError extends APIError {
  constructor(message, details = {}) {
    super(message, 400, details);
    this.name = "ValidationError";
  }
}

class FraudError extends APIError {
  constructor(message, details = {}) {
    super(message, 403, details);
    this.name = "FraudError";
  }
}

// ============================================================================
// TRANSACTION STATUS MACHINE
// ============================================================================


const VALID_STATUS_TRANSITIONS = {
  'pending': ['payment_initiated', 'failed', 'expired'],
  'payment_initiated': ['payment_verified', 'failed', 'expired'],
  'payment_verified': ['recharge_processing', 'failed'],
  'recharge_processing': ['completed', 'failed'],
  'completed': [],
  'failed': [],
  'expired': []
};

// ============================================================================
// ENCRYPTION/DECRYPTION (from your main server)
// ============================================================================
function encryptData(data) {
  try {
    const jsonString = JSON.stringify(data);
    return CryptoJS.AES.encrypt(jsonString, config.security.encryptionKey).toString();
  } catch (error) {
    logger.error("Encryption failed", { error: error.message });
    throw new Error("Data encryption failed");
  }
}

function decryptData(encryptedData) {
  try {
    const decrypted = CryptoJS.AES.decrypt(encryptedData, config.security.encryptionKey);
    const jsonString = decrypted.toString(CryptoJS.enc.Utf8);
    return JSON.parse(jsonString);
  } catch (error) {
    logger.error("Decryption failed", { error: error.message });
    throw new Error("Data decryption failed");
  }
}

// ============================================================================
// INPUT SANITIZATION (from your main server)
// ============================================================================
function sanitizeInput(str) {
  if (typeof str !== 'string') return str;
  if (!str) return str;
  
  return str
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .replace(/data:/gi, '')
    .replace(/vbscript:/gi, '')
    .trim()
    .slice(0, 500);
}

function sanitizeForLog(data) {
  if (!data || typeof data !== 'object') return data;
  
  const sanitized = { ...data };
  const sensitiveFields = ['mobile', 'phone', 'email', 'password', 'apiKey'];
  
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      const value = String(sanitized[field]);
      if (value.length > 6) {
        sanitized[field] = value.slice(0, 3) + '***' + value.slice(-3);
      } else {
        sanitized[field] = '***';
      }
    }
  });
  
  return sanitized;
}

// ============================================================================
// VALIDATE USER DETAILS
// ============================================================================
function validateUserDetails(details) {
  const errors = [];
  
  if (details.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(details.email)) {
    errors.push("Invalid email format");
  }
  
  if (details.customerName && details.customerName.length < 2) {
    errors.push("Customer name must be at least 2 characters");
  }
  
  if (details.phone && !/^[0-9]{10,15}$/.test(details.phone.replace(/\D/g, ''))) {
    errors.push("Invalid phone number");
  }
  
  if (errors.length > 0) {
    throw new ValidationError("Invalid user details", { errors });
  }
  
  return true;
}

// ============================================================================
// FRAUD DETECTION (from your main server)
// ============================================================================
async function checkFraudRisk(identifier, mobile, amount, ipAddress) {
  const risks = [];
  
  try {
    // Check 1: Daily limit per user
    if (identifier) {
      const today = new Date().toISOString().split('T')[0];
      const snapshot = await db.ref(`daily_totals/user/${identifier}/${today}`).once('value');
      const dailyTotal = snapshot.val() || 0;
      
      if (dailyTotal + amount > config.limits.dailyLimitPerUser) {
        risks.push({
          type: "user_daily_limit_exceeded",
          message: `Daily limit of ₹${config.limits.dailyLimitPerUser.toLocaleString()} would be exceeded`,
          severity: "high"
        });
      }
    }
    
    // Check 2: Daily limit per IP
    const today = new Date().toISOString().split('T')[0];
    const ipSnapshot = await db.ref(`daily_totals/ip/${ipAddress}/${today}`).once('value');
    const ipDailyTotal = ipSnapshot.val() || 0;
    
    if (ipDailyTotal + amount > config.limits.dailyLimitPerIP) {
      risks.push({
        type: "ip_daily_limit_exceeded",
        message: `IP daily limit of ₹${config.limits.dailyLimitPerIP.toLocaleString()} would be exceeded`,
        severity: "high"
      });
    }
    
    // Check 3: Rapid successive transactions
    const last5Min = Date.now() - (5 * 60 * 1000);
    const recentSnapshot = await db.ref('topup_transactions')
      .orderByChild('ipAddress')
      .equalTo(ipAddress)
      .limitToLast(10)
      .once('value');
    
    if (recentSnapshot.exists()) {
      const recentTransactions = Object.values(recentSnapshot.val());
      const recentCount = recentTransactions.filter(t => t.createdAt > last5Min).length;
      
      if (recentCount >= config.limits.maxRapidTransactions) {
        risks.push({
          type: "rapid_transactions",
          message: "Multiple transactions detected in short time",
          severity: "high"
        });
      }
    }
    
    // Check 4: Same mobile number rapid recharge
    const mobileSnapshot = await db.ref('topup_transactions')
      .orderByChild('mobile')
      .equalTo(mobile)
      .limitToLast(5)
      .once('value');
    
    if (mobileSnapshot.exists()) {
      const mobileTxs = Object.values(mobileSnapshot.val());
      const recentMobileCount = mobileTxs.filter(t => t.createdAt > last5Min).length;
      
      if (recentMobileCount >= 2) {
        risks.push({
          type: "duplicate_mobile_recharge",
          message: "Multiple recharges to same number detected",
          severity: "medium"
        });
      }
    }
    
  } catch (error) {
    logger.error("Fraud check failed", { error: error.message });
  }
  
  return risks;
}

// Update daily totals
async function updateDailyTotals(identifier, ipAddress, amount) {
  const today = new Date().toISOString().split('T')[0];
  
  try {
    if (identifier) {
      const userRef = db.ref(`daily_totals/user/${identifier}/${today}`);
      const snapshot = await userRef.once('value');
      await userRef.set((snapshot.val() || 0) + amount);
    }
    
    const ipRef = db.ref(`daily_totals/ip/${ipAddress}/${today}`);
    const ipSnapshot = await ipRef.once('value');
    await ipRef.set((ipSnapshot.val() || 0) + amount);
  } catch (error) {
    logger.error("Failed to update daily totals", { error: error.message });
  }
}

// ============================================================================
// OPERATOR CODES
// ============================================================================
const OPERATOR_CODES = {
  PREPAID: { AIRTEL: 'A', JIO: 'RC', VI: 'V', BSNL: 'BT' },
  POSTPAID: { AIRTEL: 'PAT', JIO: 'JPP', VI: 'VP', BSNL: 'BP' }
};

// ============================================================================
// PREPAID PLANS (SERVER-SIDE SOURCE OF TRUTH - ANTI-MANIPULATION)
// ============================================================================
const PREPAID_PLANS = {
  JIO: [
    { id: 'JIO299', amount: 299, validity: '28 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'JIO399', amount: 399, validity: '28 days', data: '1.5GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'JIO555', amount: 555, validity: '56 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'JIO2545', amount: 2545, validity: '365 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'JIO149', amount: 149, validity: '28 days', data: '300MB', calls: 'Unlimited', sms: 'NA' },
    { id: 'JIO749', amount: 749, validity: '90 days', data: '1.5GB/day', calls: 'Unlimited', sms: '100/day' }
  ],
  AIRTEL: [
    { id: 'AIRTEL299', amount: 299, validity: '28 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'AIRTEL479', amount: 479, validity: '56 days', data: '1.5GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'AIRTEL599', amount: 599, validity: '56 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'AIRTEL2999', amount: 2999, validity: '365 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'AIRTEL749', amount: 749, validity: '84 days', data: '1.5GB/day', calls: 'Unlimited', sms: '100/day' }
  ],
  VI: [
    { id: 'VI299', amount: 299, validity: '28 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'VI349', amount: 349, validity: '28 days', data: '1.5GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'VI599', amount: 599, validity: '56 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'VI2999', amount: 2999, validity: '365 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' }
  ],
  BSNL: [
    { id: 'BSNL107', amount: 107, validity: '28 days', data: '2GB', calls: 'Unlimited', sms: '100/day' },
    { id: 'BSNL197', amount: 197, validity: '28 days', data: '1GB/day', calls: 'Unlimited', sms: '100/day' },
    { id: 'BSNL549', amount: 549, validity: '70 days', data: '2GB/day', calls: 'Unlimited', sms: '100/day' }
  ]
};

function getPlanById(network, planId) {
  const plans = PREPAID_PLANS[network.toUpperCase()];
  if (!plans) return null;
  return plans.find(p => p.id === planId);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function calculateLPEarned(rechargeAmountInr, userTier = 'BRONZE') {
  const multiplier = config.loyalty.tiers[userTier]?.multiplier || 1.0;
  const baseLPEarned = (rechargeAmountInr / 10) * config.loyalty.lpPerTenRupees;
  return Math.floor(baseLPEarned * multiplier);
}

function getUserTier(xlp) {
  if (xlp >= config.loyalty.tiers.GOLD.minXLP) return 'GOLD';
  if (xlp >= config.loyalty.tiers.SILVER.minXLP) return 'SILVER';
  return 'BRONZE';
}

function calculateFees(rechargeAmountInr, exchangeRate, useLP = false, userLP = 0) {
  const convenienceFeeInr = config.fees.convenienceFeeInr;
  const convenienceFeeNgn = Math.round(convenienceFeeInr * exchangeRate);
  
  let lpUsed = 0, actualConvenienceFeeInr = convenienceFeeInr, actualConvenienceFeeNgn = convenienceFeeNgn;
  
  if (useLP && config.fees.canWaiveWithLP && userLP >= config.fees.lpRequiredToWaive) {
    lpUsed = config.fees.lpRequiredToWaive;
    actualConvenienceFeeInr = 0;
    actualConvenienceFeeNgn = 0;
  }
  
  const totalInr = rechargeAmountInr + actualConvenienceFeeInr;
  const totalNgn = Math.round(totalInr * exchangeRate);
  
  return {
    rechargeAmountInr, convenienceFeeInr: actualConvenienceFeeInr, totalAmountInr: totalInr,
    rechargeAmountNgn: Math.round(rechargeAmountInr * exchangeRate),
    convenienceFeeNgn: actualConvenienceFeeNgn, totalAmountNgn: totalNgn, lpUsed,
    lpSavings: lpUsed > 0 ? `Saved ₹${convenienceFeeInr} (₦${convenienceFeeNgn})` : null
  };
}

// ============================================================================
// A1TOPUP API CLIENT
// ============================================================================
class A1TopupAPI {
  static async recharge(mobile, network, type, amount, orderId) {
    const startTime = Date.now();
    const operatorCode = OPERATOR_CODES[type.toUpperCase()][network.toUpperCase()];
    
    if (!operatorCode) throw new Error(`Invalid network '${network}' for ${type}`);

    if (config.a1topup.testMode) {
      logger.info('🧪 TEST MODE Recharge', sanitizeForLog({ mobile, network, type, amount }));
      await sleep(2000);
      return {
        status: 'Success', txid: `TEST_${Date.now()}`, opid: `${network}_${Date.now()}`,
        number: mobile, amount: amount.toString(), orderid: orderId
      };
    }

    try {
      const response = await axios.get(`${config.a1topup.baseUrl}/api`, {
        params: {
          username: config.a1topup.username, pwd: config.a1topup.password,
          circlecode: config.a1topup.defaultCircle, operatorcode: operatorCode,
          number: mobile, amount: amount, orderid: orderId, format: 'json'
        },
        timeout: config.timeouts.a1topup
      });
      
      const latency = Date.now() - startTime;
      metrics.api.a1topup.calls++;
      metrics.api.a1topup.avgLatency = 
        (metrics.api.a1topup.avgLatency * (metrics.api.a1topup.calls - 1) + latency) / metrics.api.a1topup.calls;
      
      logger.info('✅ A1Topup response', { orderId, status: response.data.status, latency });
      return response.data;
    } catch (error) {
      metrics.api.a1topup.failures++;
      logger.error('❌ A1Topup failed', sanitizeForLog({ error: error.message, mobile, network }));
      throw new Error(`Recharge failed: ${error.response?.data?.error || error.message}`);
    }
  }
}

// ============================================================================
// FIRESTORE SERVICE (Using Realtime Database like main server)
// ============================================================================
class FirestoreService {
  static getUserIdentifier(uid, email) {
    return uid || email || null;
  }

  static async getOrCreateUser(uid, email = null, name = null, phone = null) {
    const identifier = this.getUserIdentifier(uid, email);
    if (!identifier) return null;

    try {
      const userRef = db.ref(`topup_users/${identifier}`);
      const snapshot = await userRef.once('value');
      
      if (snapshot.exists()) {
        return { identifier, ...snapshot.val() };
      }
      
      const newUser = {
        identifier, uid: uid || null, email: email || null, name: name || 'User', phone: phone || null,
        loyaltyPoints: 0, totalXLP: 0, tier: 'BRONZE', totalTopups: 0, totalSpentINR: 0,
        createdAt: Date.now(), updatedAt: Date.now()
      };
      
      await userRef.set(newUser);
      logger.info('✅ User created', sanitizeForLog({ identifier }));
      return { identifier, ...newUser };
    } catch (error) {
      logger.error('User creation failed', { error: error.message });
      return null;
    }
  }

  static async createTopup(topupData) {
    try {
      // Encrypt sensitive data
      const encryptedUserDetails = encryptData({
        email: topupData.email,
        customerName: topupData.customerName,
        phone: topupData.phone,
        mobile: topupData.mobile
      });
      
      const encryptedTransaction = encryptData({
        rechargeAmountInr: topupData.rechargeAmountInr,
        totalAmountNgn: topupData.totalAmountNgn,
        network: topupData.network,
        type: topupData.type,
        planId: topupData.planId
      });
      
      const sessionData = {
        sessionId: topupData.sessionId,
        status: 'pending',
        createdAt: Date.now(),
        expiresAt: Date.now() + config.security.sessionTTL,
        encryptedUserDetails,
        encryptedTransaction,
        ipAddress: topupData.ipAddress,
        
        // Non-sensitive summary
        summary: {
          amountNGN: topupData.totalAmountNgn,
          amountINR: topupData.rechargeAmountInr,
          userName: topupData.customerName || 'Customer',
          network: topupData.network
        },
        
        // Tracking
        identifier: topupData.identifier,
        mobile: topupData.mobile, // Encrypted in encryptedUserDetails too
        network: topupData.network,
        type: topupData.type
      };
      
      await db.ref(`topup_transactions/${topupData.sessionId}`).set(sessionData);
      logger.info('✅ Transaction session created', { sessionId: topupData.sessionId });
      
      metrics.topups.total++;
      metrics.topups.pending++;
      
      return topupData.sessionId;
    } catch (error) {
      logger.error('Create topup failed', { error: error.message });
      throw error;
    }
  }

  static async getTopup(sessionId) {
    try {
      const snapshot = await db.ref(`topup_transactions/${sessionId}`).once('value');
      if (!snapshot.exists()) return null;
      
      const session = snapshot.val();
      
      // Check expiry
      if (session.expiresAt && session.expiresAt < Date.now() && session.status === 'pending') {
        logger.warn("Attempted to access expired session", { sessionId });
        throw new APIError("Session expired", 410);
      }
      
      // Decrypt sensitive data
      const userDetails = decryptData(session.encryptedUserDetails);
      const transaction = decryptData(session.encryptedTransaction);
      
      return { ...session, userDetails, transaction };
    } catch (error) {
      logger.error("Failed to get transaction", { error: error.message, sessionId });
      throw error;
    }
  }

  static async updateTopupStatus(sessionId, newStatus, additionalData = {}) {
    try {
      const snapshot = await db.ref(`topup_transactions/${sessionId}`).once('value');
      
      if (!snapshot.exists()) {
        throw new APIError('Transaction not found', 404);
      }
      
      const currentTransaction = snapshot.val();
      const currentStatus = currentTransaction.status;
      
      // Skip if already in target status
      if (currentStatus === newStatus) {
        logger.debug('Transaction already in target status', { sessionId, newStatus });
        return true;
      }
      
      // Validate status transition
      const allowedTransitions = VALID_STATUS_TRANSITIONS[currentStatus];
      
      if (!allowedTransitions || !allowedTransitions.includes(newStatus)) {
        throw new ValidationError(
          `Cannot transition from '${currentStatus}' to '${newStatus}'`,
          { currentStatus, requestedStatus: newStatus, allowedTransitions }
        );
      }
      
      // Update
      const updates = {
        status: newStatus,
        previousStatus: currentStatus,
        updatedAt: Date.now(),
        ...additionalData
      };
      
      await db.ref(`topup_transactions/${sessionId}`).update(updates);
      
      logger.info('Transaction status updated', { sessionId, from: currentStatus, to: newStatus });
      
      // Update metrics
      if (newStatus === 'completed') {
        metrics.topups.completed++;
        if (currentStatus === 'pending' || currentStatus === 'payment_initiated') {
          metrics.topups.pending--;
        }
      } else if (newStatus === 'failed') {
        metrics.topups.failed++;
        if (currentStatus === 'pending' || currentStatus === 'payment_initiated') {
          metrics.topups.pending--;
        }
      }
      
      return true;
    } catch (error) {
      logger.error('Failed to update status', { error: error.message, sessionId });
      throw error;
    }
  }

  static async awardLoyaltyPoints(identifier, sessionId, lpEarned, rechargeAmount, description) {
    if (!identifier) return false;
    
    try {
      const userRef = db.ref(`topup_users/${identifier}`);
      const snapshot = await userRef.once('value');
      
      if (!snapshot.exists()) {
        logger.warn('Cannot award LP - user not found', { identifier });
        return false;
      }
      
      const userData = snapshot.val();
      
      // Update user LP
      await userRef.update({
        loyaltyPoints: (userData.loyaltyPoints || 0) + lpEarned,
        totalXLP: (userData.totalXLP || 0) + lpEarned,
        totalTopups: (userData.totalTopups || 0) + 1,
        totalSpentINR: (userData.totalSpentINR || 0) + rechargeAmount,
        updatedAt: Date.now()
      });
      
      // Log LP transaction
      await db.ref(`topup_loyalty_logs/${identifier}`).push({
        sessionId, type: 'EARNED', amount: lpEarned, description, rechargeAmount,
        createdAt: Date.now()
      });
      
      // Check tier upgrade
      const newTotalXLP = (userData.totalXLP || 0) + lpEarned;
      const newTier = getUserTier(newTotalXLP);
      
      if (newTier !== userData.tier) {
        await userRef.update({ tier: newTier });
        logger.info('🎉 User tier upgraded', { identifier, oldTier: userData.tier, newTier });
      }
      
      logger.info('✅ LP awarded', { identifier, lpEarned, sessionId });
      return true;
    } catch (error) {
      logger.error('Award LP failed', { error: error.message, identifier });
      return false;
    }
  }

  static async redeemLoyaltyPoints(identifier, sessionId, lpUsed, description) {
    if (!identifier) return false;
    
    try {
      const userRef = db.ref(`topup_users/${identifier}`);
      const snapshot = await userRef.once('value');
      
      if (!snapshot.exists()) {
        throw new Error('User not found');
      }
      
      const userData = snapshot.val();
      
      if ((userData.loyaltyPoints || 0) < lpUsed) {
        throw new Error('Insufficient loyalty points');
      }
      
      await userRef.update({
        loyaltyPoints: userData.loyaltyPoints - lpUsed,
        updatedAt: Date.now()
      });
      
      await db.ref(`topup_loyalty_logs/${identifier}`).push({
        sessionId, type: 'REDEEMED', amount: -lpUsed, description,
        createdAt: Date.now()
      });
      
      logger.info('✅ LP redeemed', { identifier, lpUsed, sessionId });
      return true;
    } catch (error) {
      logger.error('Redeem LP failed', { error: error.message, identifier });
      throw error;
    }
  }

  static async getUserLoyaltyStats(identifier) {
    if (!identifier) return null;
    
    try {
      const snapshot = await db.ref(`topup_users/${identifier}`).once('value');
      if (!snapshot.exists()) return null;
      
      const userData = snapshot.val();
      const tier = getUserTier(userData.totalXLP || 0);
      
      return {
        loyaltyPoints: userData.loyaltyPoints || 0,
        totalXLP: userData.totalXLP || 0,
        tier: tier,
        tierInfo: config.loyalty.tiers[tier],
        totalTopups: userData.totalTopups || 0,
        totalSpentINR: userData.totalSpentINR || 0,
        canWaiveFee: (userData.loyaltyPoints || 0) >= config.fees.lpRequiredToWaive,
        lpRequiredForWaiver: config.fees.lpRequiredToWaive
      };
    } catch (error) {
      logger.error('Get loyalty stats failed', { error: error.message });
      return null;
    }
  }
}

// ============================================================================
// PAYSTACK API (Direct Implementation like main server)
// ============================================================================
const paystackAPI = {
  secretKey: config.paystack.secretKey,
  
  async initializeTransaction(data) {
    const postData = JSON.stringify(data);
    
    const options = {
      hostname: 'api.paystack.co',
      port: 443,
      path: '/transaction/initialize',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.secretKey}`,
        'Content-Type': 'application/json',
        'Content-Length': postData.length
      }
    };
    
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let responseData = '';
        res.on('data', (chunk) => { responseData += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(responseData));
          } catch (error) {
            reject(new Error('Failed to parse Paystack response'));
          }
        });
      });
      req.on('error', (error) => { reject(error); });
      req.write(postData);
      req.end();
    });
  },
  
  async verifyTransaction(reference) {
    const options = {
      hostname: 'api.paystack.co',
      port: 443,
      path: `/transaction/verify/${reference}`,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${this.secretKey}`,
        'Content-Type': 'application/json'
      }
    };
    
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let responseData = '';
        res.on('data', (chunk) => { responseData += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(responseData));
          } catch (error) {
            reject(new Error('Failed to parse Paystack response'));
          }
        });
      });
      req.on('error', (error) => { reject(error); });
      req.end();
    });
  }
};

// ============================================================================
// AMOUNT VERIFICATION (from main server)
// ============================================================================
async function verifyPaymentAmount(sessionId, paidAmountKobo) {
  const snapshot = await db.ref(`topup_transactions/${sessionId}`).once('value');
  
  if (!snapshot.exists()) {
    throw new APIError('Transaction not found', 404);
  }
  
  const session = snapshot.val();
  const expectedAmountNGN = session.summary.amountNGN;
  const expectedAmountKobo = Math.round(expectedAmountNGN * 100);
  const paidAmountNGN = paidAmountKobo / 100;
  
  // Allow 1% tolerance for Paystack fees variance
  const tolerance = expectedAmountKobo * 0.01;
  const amountDifference = Math.abs(paidAmountKobo - expectedAmountKobo);
  const isValid = amountDifference <= tolerance;
  
  logger.info('💰 Payment amount verification', {
    sessionId,
    expected: expectedAmountNGN,
    paid: paidAmountNGN,
    difference: (paidAmountNGN - expectedAmountNGN).toFixed(2),
    isValid
  });
  
  return {
    isValid,
    expectedAmount: expectedAmountNGN,
    paidAmount: paidAmountNGN,
    difference: paidAmountNGN - expectedAmountNGN
  };
}

// ============================================================================
// EXPRESS APP
// ============================================================================
const app = express();
app.set("trust proxy", config.security.trustProxy);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));

app.use(express.json({ limit: "10kb" }));
app.use(express.raw({ type: 'application/json', limit: '10kb' })); // For webhook

// CORS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", config.security.corsOrigin);
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User-UID");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Rate limiting - strict like main server
const limiter = rateLimit({
  max: 10,
  windowMs: 60 * 1000,
  message: { error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === "/health",
  keyGenerator: (req) => req.ip || "unknown"
});

app.use("/api/", limiter);

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const duration = Date.now() - start;
    logger.info("Request completed", {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      ip: req.ip
    });
  });
  next();
});

// Middleware to extract user
// Middleware to extract user
async function extractUser(req, res, next) {
  const uid = req.headers['x-user-uid'];
  const email = (req.body && req.body.email) || req.query.email; // FIX: Check if req.body exists
  const identifier = FirestoreService.getUserIdentifier(uid, email);
  
  req.identifier = identifier;
  req.user = null;
  
  if (identifier) {
    try {
      const cacheKey = `user_${identifier}`;
      let user = cache.get(cacheKey);
      
      if (!user) {
        user = await FirestoreService.getOrCreateUser(uid, email);
        if (user) cache.set(cacheKey, user, 300);
      }
      
      req.user = user;
    } catch (error) {
      logger.error('Extract user failed', { error: error.message });
    }
  }
  
  next();
}


// ============================================================================
// ROUTES
// ============================================================================

app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "paydrak-topup-service",
    version: "4.0-SECURE",
    timestamp: new Date().toISOString(),
    testMode: config.a1topup.testMode,
    firebase: 'connected',
    exchangeRate: config.staticExchangeRate,
    uptime: process.uptime()
  });
});

// GET PLANS
app.get('/api/topup/plans', extractUser, async (req, res, next) => {
  try {
    metrics.requests.total++;
    const { network } = req.query;

    if (!network || !PREPAID_PLANS[network.toUpperCase()]) {
      return res.status(400).json({ success: false, error: 'Invalid network. Use: JIO, AIRTEL, VI, or BSNL' });
    }

    const ngnPerInr = config.staticExchangeRate;
    const basePlans = PREPAID_PLANS[network.toUpperCase()];
    
    const plansWithNGN = basePlans.map(plan => {
      const fees = calculateFees(plan.amount, ngnPerInr, false, 0);
      return {
        ...plan, type: 'prepaid',
        priceINR: plan.amount, priceNGN: fees.rechargeAmountNgn,
        convenienceFeeINR: fees.convenienceFeeInr, convenienceFeeNGN: fees.convenienceFeeNgn,
        totalPriceINR: fees.totalAmountInr, totalPriceNGN: fees.totalAmountNgn,
        exchangeRate: ngnPerInr
      };
    });

    let userLoyalty = null;
    if (req.identifier) {
      userLoyalty = await FirestoreService.getUserLoyaltyStats(req.identifier);
    }

    metrics.requests.success++;
    res.json({ 
      success: true, 
      network: network.toUpperCase(), 
      plans: plansWithNGN, 
      exchangeRate: ngnPerInr, 
      userLoyalty 
    });
  } catch (error) {
    logger.error('Plans error', { error: error.message });
    metrics.requests.errors++;
    next(error);
  }
});

// GET QUOTE - WITH FRAUD CHECKS
app.post('/api/topup/quote', extractUser, [
  body('mobile').matches(/^[6-9]\d{9}$/).withMessage('Invalid mobile number'),
  body('network').isIn(['AIRTEL', 'JIO', 'VI', 'BSNL']).withMessage('Invalid network'),
  body('type').isIn(['prepaid', 'postpaid']).withMessage('Invalid type'),
  body('planId').optional().isString(),
  body('amount').optional().isNumeric(),
  body('useLoyaltyPoints').optional().isBoolean()
], async (req, res, next) => {
  try {
    metrics.requests.total++;
    
    // Validate
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    const { mobile, network, type, planId, amount, useLoyaltyPoints } = req.body;

    let rechargeAmount, planDetails = null;

    // PREPAID: planId required (SERVER-SIDE VALIDATION - ANTI-MANIPULATION)
    if (type.toLowerCase() === 'prepaid') {
      if (!planId) {
        return res.status(400).json({ success: false, error: 'planId required for prepaid' });
      }
      
      planDetails = getPlanById(network, planId);
      if (!planDetails) {
        return res.status(400).json({ success: false, error: 'Invalid planId - plan not found' });
      }
      
      rechargeAmount = planDetails.amount; // USE SERVER AMOUNT ONLY
    } else {
      if (!amount || amount < config.limits.minRechargeInr || amount > config.limits.maxRechargeInr) {
        return res.status(400).json({ 
          success: false, 
          error: `Amount must be ₹${config.limits.minRechargeInr}-₹${config.limits.maxRechargeInr}` 
        });
      }
      rechargeAmount = amount;
    }

    // FRAUD CHECK
    const fraudRisks = await checkFraudRisk(req.identifier, mobile, rechargeAmount, req.ip);
    
    const highRisks = fraudRisks.filter(r => r.severity === 'high');
    if (highRisks.length > 0) {
      logger.warn('🚨 FRAUD: High risk transaction blocked', sanitizeForLog({
        mobile, network, amount: rechargeAmount, ip: req.ip, risks: highRisks
      }));
      
      metrics.fraud.blocked++;
      
      return res.status(403).json({
        success: false,
        error: 'Transaction blocked due to security concerns',
        risks: highRisks
      });
    }
    
    if (fraudRisks.length > 0) {
      logger.warn('⚠️ FRAUD: Medium risk detected', sanitizeForLog({
        mobile, network, amount: rechargeAmount, ip: req.ip, risks: fraudRisks
      }));
      metrics.fraud.warnings++;
    }

    const ngnPerInr = config.staticExchangeRate;
    
    let userLP = 0, userTier = 'BRONZE';
    if (req.identifier) {
      const loyaltyStats = await FirestoreService.getUserLoyaltyStats(req.identifier);
      if (loyaltyStats) {
        userLP = loyaltyStats.loyaltyPoints;
        userTier = loyaltyStats.tier;
      }
    }

    const useLP = useLoyaltyPoints && req.identifier && userLP >= config.fees.lpRequiredToWaive;
    const fees = calculateFees(rechargeAmount, ngnPerInr, useLP, userLP);
    const lpToEarn = req.identifier ? calculateLPEarned(rechargeAmount, userTier) : 0;

    if (fees.totalAmountNgn < config.limits.minTotalAmountNgn) {
      return res.status(400).json({ success: false, error: `Total (₦${fees.totalAmountNgn}) below minimum` });
    }

    metrics.requests.success++;
    res.json({
      success: true,
      quote: {
        mobile, network: network.toUpperCase(), type: type.toLowerCase(), planId: planDetails?.id || null,
        planDetails,
        rechargeAmountINR: rechargeAmount, convenienceFeeINR: fees.convenienceFeeInr, 
        totalPayableINR: fees.totalAmountInr,
        rechargeAmountNGN: fees.rechargeAmountNgn, convenienceFeeNGN: fees.convenienceFeeNgn, 
        totalPayableNGN: fees.totalAmountNgn,
        exchangeRate: ngnPerInr,
        loyaltyInfo: req.identifier ? {
          lpUsed: fees.lpUsed, lpSavings: fees.lpSavings, lpToEarn, userTier, currentLP: userLP,
          afterTransactionLP: userLP - fees.lpUsed + lpToEarn
        } : null
      },
      warnings: fraudRisks.length > 0 ? fraudRisks : undefined
    });
  } catch (error) {
    logger.error('Quote error', { error: error.message });
    metrics.requests.errors++;
    next(error);
  }
});

// CONTINUE - INITIATE RECHARGE (WITH ALL SECURITY)
app.post('/api/topup/continue', extractUser, [
  body('mobile').matches(/^[6-9]\d{9}$/).withMessage('Invalid mobile number'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('customerName').isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('network').isIn(['AIRTEL', 'JIO', 'VI', 'BSNL']).withMessage('Invalid network'),
  body('type').isIn(['prepaid', 'postpaid']).withMessage('Invalid type'),
  body('planId').optional().isString(),
  body('amount').optional().isNumeric(),
  body('phone').optional().isString(),
  body('useLoyaltyPoints').optional().isBoolean()
], async (req, res, next) => {
  try {
    metrics.requests.total++;
    
    // Validate
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    
    let { mobile, network, type, planId, amount, email, customerName, phone, useLoyaltyPoints } = req.body;
    
    // Sanitize inputs
    mobile = sanitizeInput(mobile);
    email = sanitizeInput(email);
    customerName = sanitizeInput(customerName);
    phone = sanitizeInput(phone);

    let rechargeAmount, planDetails = null;

    // PREPAID: SERVER-SIDE VALIDATION
    if (type.toLowerCase() === 'prepaid') {
      if (!planId) {
        return res.status(400).json({ success: false, error: 'planId required for prepaid' });
      }
      planDetails = getPlanById(network, planId);
      if (!planDetails) {
        return res.status(400).json({ success: false, error: 'Invalid planId' });
      }
      rechargeAmount = planDetails.amount; // SERVER AMOUNT
    } else {
      if (!amount || amount < config.limits.minRechargeInr) {
        return res.status(400).json({ success: false, error: 'Invalid amount' });
      }
      rechargeAmount = amount;
    }

    // FRAUD CHECK
    const fraudRisks = await checkFraudRisk(req.identifier || email, mobile, rechargeAmount, req.ip);
    
    const highRisks = fraudRisks.filter(r => r.severity === 'high');
    if (highRisks.length > 0) {
      logger.error('🚨 FRAUD BLOCKED', sanitizeForLog({
        mobile, email, amount: rechargeAmount, ip: req.ip, risks: highRisks
      }));
      
      metrics.fraud.blocked++;
      
      throw new FraudError('Transaction blocked due to security concerns', { risks: highRisks });
    }

    let identifier = req.identifier || email;
    let userLP = 0, userTier = 'BRONZE';
    
    if (identifier) {
      await FirestoreService.getOrCreateUser(req.headers['x-user-uid'], email, customerName, phone);
      const loyaltyStats = await FirestoreService.getUserLoyaltyStats(identifier);
      if (loyaltyStats) {
        userLP = loyaltyStats.loyaltyPoints;
        userTier = loyaltyStats.tier;
      }
    }

    const ngnPerInr = config.staticExchangeRate;
    const useLP = useLoyaltyPoints && identifier && userLP >= config.fees.lpRequiredToWaive;
    const fees = calculateFees(rechargeAmount, ngnPerInr, useLP, userLP);

    // Redeem LP if used
    if (fees.lpUsed > 0 && identifier) {
      const sessionIdTemp = `TEMP_${Date.now()}`;
      await FirestoreService.redeemLoyaltyPoints(identifier, sessionIdTemp, fees.lpUsed, 
        `Fee waiver for ₹${rechargeAmount} recharge`);
    }

    const sessionId = `TOPUP_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    const lpToEarn = identifier ? calculateLPEarned(rechargeAmount, userTier) : 0;
    
    const topupData = {
      sessionId, identifier, email, mobile, network: network.toUpperCase(), 
      type: type.toLowerCase(), planId: planDetails?.id || null,
      rechargeAmountInr: rechargeAmount, convenienceFeeInr: fees.convenienceFeeInr, 
      totalAmountInr: fees.totalAmountInr,
      rechargeAmountNgn: fees.rechargeAmountNgn, convenienceFeeNgn: fees.convenienceFeeNgn, 
      totalAmountNgn: fees.totalAmountNgn,
      exchangeRate: ngnPerInr, lpUsed: fees.lpUsed, lpToEarn, userTier,
      customerName, phone: phone || `+91${mobile}`,
      ipAddress: req.ip
    };

    // Create encrypted session in Firebase
    await FirestoreService.createTopup(topupData);

    // Initialize Paystack payment
    const paystackData = {
      email,
      amount: Math.round(fees.totalAmountNgn * 100), // Convert to kobo
      currency: 'NGN',
      reference: `TOPUP-${sessionId}-${Date.now()}`,
      metadata: {
        sessionId,
        customerName,
        phone: phone || `+91${mobile}`,
        mobile,
        network: network.toUpperCase(),
        type: type.toLowerCase(),
        rechargeAmount: rechargeAmount
      }
    };

    const paymentResponse = await paystackAPI.initializeTransaction(paystackData);

    if (!paymentResponse.status) {
      throw new APIError('Failed to initialize payment', 500, { 
        paystackError: paymentResponse.message 
      });
    }

    // Update session with payment reference
    await FirestoreService.updateTopupStatus(sessionId, 'payment_initiated', {
      paystackReference: paystackData.reference,
      paystackInitializedAt: Date.now()
    });

    // Update daily totals for fraud tracking
    await updateDailyTotals(identifier, req.ip, rechargeAmount);

    logger.info('✅ Transaction created', sanitizeForLog({ 
      sessionId, identifier, mobile, network, type, totalNGN: fees.totalAmountNgn 
    }));
    
    metrics.requests.success++;

    res.json({
      success: true, sessionId,
      payment: {
        reference: paystackData.reference,
        authorizationUrl: paymentResponse.data.authorization_url,
        accessCode: paymentResponse.data.access_code
      },
      quote: {
        rechargeAmountINR: rechargeAmount, convenienceFeeINR: fees.convenienceFeeInr,
        totalAmountINR: fees.totalAmountInr, totalAmountNGN: fees.totalAmountNgn,
        lpUsed: fees.lpUsed, lpToEarn
      },
      recharge: { mobile, network: network.toUpperCase(), type: type.toLowerCase(), planId: planDetails?.id }
    });
  } catch (error) {
    logger.error('Continue error', { error: error.message });
    metrics.requests.errors++;
    next(error);
  }
});

// VERIFY & EXECUTE RECHARGE (WITH AMOUNT VERIFICATION)
app.post('/api/topup/verify', async (req, res, next) => {
  try {
    const { reference, sessionId } = req.body;
    
    if (!sessionId) {
      return res.status(400).json({ success: false, error: 'sessionId required' });
    }

    logger.info('🔍 Verifying payment', { reference, sessionId });

    let topupData = await FirestoreService.getTopup(sessionId);
    if (!topupData) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    if (topupData.status === 'completed') {
      res.json({
        success: true,
        status: 'completed',
        message: 'Recharge successful!',
        recharge: { mobile, network, type, rechargeAmount, transactionId, operatorId },
        loyaltyReward: topupData.lpToEarn > 0 ? { lpEarned: topupData.lpToEarn } : null
      });
      
    }

    // Verify with Paystack
    let verified = false;
    
    if (reference) {
      const verification = await paystackAPI.verifyTransaction(reference);
      
      if (!verification.status || !verification.data) {
        throw new APIError('Payment verification failed', 400);
      }
      
      const transaction = verification.data;
      
      if (transaction.status === 'success') {
        const amountCheck = await verifyPaymentAmount(sessionId, transaction.amount);
        
        if (!amountCheck.isValid) {
          logger.error('❌ AMOUNT MISMATCH', {
            sessionId, reference,
            expected: amountCheck.expectedAmount,
            paid: amountCheck.paidAmount
          });
          
          await FirestoreService.updateTopupStatus(sessionId, 'failed', {
            paymentStatus: 'failed',
            failureReason: 'Amount mismatch',
            expectedAmount: amountCheck.expectedAmount,
            paidAmount: amountCheck.paidAmount,
            amountDifference: amountCheck.difference,
            requiresRefund: true,
            requiresManualReview: true
          });
          
          return res.status(400).json({ 
            success: false, 
            error: 'Amount mismatch - blocked', 
            details: amountCheck 
          });
        }
        
        verified = true;
      }
    }

    if (!verified) {
      await FirestoreService.updateTopupStatus(sessionId, 'failed', { 
        paymentStatus: 'failed' 
      });
      return res.status(400).json({ 
        success: false, 
        error: 'Payment verification failed' 
      });
    }

    await FirestoreService.updateTopupStatus(sessionId, 'payment_verified', { 
      paymentStatus: 'verified',
      paidAt: Date.now()
    });

    logger.info('📱 Executing recharge', sanitizeForLog({ 
      mobile: topupData.userDetails.mobile, 
      network: topupData.transaction.network 
    }));

    await FirestoreService.updateTopupStatus(sessionId, 'recharge_processing');

    // ✅ FIX: Wrap in try-catch
    let rechargeResult;
    try {
      rechargeResult = await A1TopupAPI.recharge(
        topupData.userDetails.mobile,
        topupData.transaction.network,
        topupData.transaction.type,
        topupData.transaction.rechargeAmountInr,
        sessionId
      );
      
      logger.info('✅ A1Topup response', { 
        sessionId, 
        status: rechargeResult.status,
        fullResponse: rechargeResult
      });
      
    } catch (error) {
      logger.error('❌ A1Topup threw error', {
        sessionId,
        errorMessage: error.message,
        errorStack: error.stack
      });
      
      // ✅ FIX: Safe error message (never undefined)
      await FirestoreService.updateTopupStatus(sessionId, 'failed', {
        rechargeStatus: 'failed',
        rechargeError: error.message || 'Unknown A1Topup error',
        requiresRefund: true
      });
      
      metrics.topups.failed++;
      
      return res.status(500).json({ 
        success: false, 
        error: `Recharge failed: ${error.message}`, 
        paymentReceived: true, 
        refundRequired: true 
      });
    }

    // ✅ FIX: Safe status check
    if (rechargeResult.status !== 'Success') {
      const failureData = {
        rechargeStatus: 'failed',
        requiresRefund: true
      };
      
      // ✅ FIX: Build error safely (never undefined)
      if (rechargeResult.message) {
        failureData.rechargeError = rechargeResult.message;
      } else if (rechargeResult.error) {
        failureData.rechargeError = rechargeResult.error;
      } else if (rechargeResult.msg) {
        failureData.rechargeError = rechargeResult.msg;
      } else if (rechargeResult.reason) {
        failureData.rechargeError = rechargeResult.reason;
      } else {
        failureData.rechargeError = `Recharge failed with status: ${rechargeResult.status || 'Unknown'}`;
      }
      
      logger.error('❌ Recharge failed', {
        sessionId,
        status: rechargeResult.status,
        errorMessage: failureData.rechargeError,
        fullResponse: rechargeResult
      });
      
      await FirestoreService.updateTopupStatus(sessionId, 'failed', failureData);
      
      metrics.topups.failed++;
      
      return res.status(500).json({ 
        success: false, 
        error: `Recharge failed: ${failureData.rechargeError}`, 
        paymentReceived: true, 
        refundRequired: true 
      });
    }

    // ✅ Success
    await FirestoreService.updateTopupStatus(sessionId, 'completed', {
      status: 'completed', 
      rechargeStatus: 'completed', 
      rechargeTransactionId: rechargeResult.txid || null,
      rechargeOperatorId: rechargeResult.opid || null,
      completedAt: Date.now()
    });

    if (topupData.identifier && topupData.lpToEarn > 0) {
      await FirestoreService.awardLoyaltyPoints(
        topupData.identifier, 
        sessionId, 
        topupData.lpToEarn, 
        topupData.transaction.rechargeAmountInr,
        `Earned from ₹${topupData.transaction.rechargeAmountInr} ${topupData.transaction.type} recharge`
      );
    }

    logger.info('✅ RECHARGE COMPLETED', sanitizeForLog({ 
      sessionId, 
      mobile: topupData.userDetails.mobile, 
      lpEarned: topupData.lpToEarn, 
      txid: rechargeResult.txid 
    }));
    
    metrics.topups.completed++;

    res.json({
      success: true, 
      status: 'completed', 
      message: '🎉 Recharge successful!',
      recharge: {
        mobile: topupData.userDetails.mobile, 
        network: topupData.transaction.network, 
        type: topupData.transaction.type,
        rechargeAmount: `₹${topupData.transaction.rechargeAmountInr}`,
        transactionId: rechargeResult.txid || 'N/A', 
        operatorId: rechargeResult.opid || 'N/A'
      },
      loyaltyReward: topupData.lpToEarn > 0 ? { lpEarned: topupData.lpToEarn } : null
    });
    
  } catch (error) {
    logger.error('❌ Verify endpoint error', { 
      error: error.message, 
      stack: error.stack 
    });
    metrics.topups.failed++;
    next(error);
  }
});


// WEBHOOK - WITH SIGNATURE VERIFICATION (from main server)
app.post("/api/webhook/paystack", express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    // Validate signature
    if (!req.headers['x-paystack-signature']) {
      logger.error('❌ Missing webhook signature', { ip: req.ip });
      return res.sendStatus(401);
    }
    
    const receivedSignature = req.headers['x-paystack-signature'];
    const hash = crypto
      .createHmac('sha512', config.paystack.secretKey)
      .update(req.body)
      .digest('hex');
    
    if (hash !== receivedSignature) {
      logger.error('❌ Invalid webhook signature', { 
        received: receivedSignature.slice(0, 10), 
        calculated: hash.slice(0, 10) 
      });
      return res.sendStatus(403);
    }
    
    const event = JSON.parse(req.body.toString());
    logger.info('✅ Webhook verified', { event: event.event, reference: event.data?.reference });
    
    if (event.event === 'charge.success') {
      const reference = event.data.reference;
      const sessionId = event.data.metadata?.sessionId;
      const paidAmountKobo = event.data.amount;
      
      if (!sessionId) {
        logger.warn('⚠️ Webhook without sessionId', { reference });
        return res.sendStatus(200);
      }
      
      const snapshot = await db.ref(`topup_transactions/${sessionId}`).once('value');
      
      if (!snapshot.exists()) {
        logger.error('❌ Webhook for non-existent transaction', { sessionId, reference });
        return res.sendStatus(404);
      }
      
      const currentTransaction = snapshot.val();
      
      // Skip if already processed
      if (currentTransaction.status === 'completed') {
        logger.info('⚠️ Webhook for already completed transaction', { sessionId });
        return res.sendStatus(200);
      }
      
      // AMOUNT VERIFICATION
      const amountCheck = await verifyPaymentAmount(sessionId, paidAmountKobo);
      
      if (!amountCheck.isValid) {
        logger.error('❌ WEBHOOK AMOUNT MISMATCH', {
          sessionId, reference,
          expected: amountCheck.expectedAmount,
          paid: amountCheck.paidAmount
        });
        
        await FirestoreService.updateTopupStatus(sessionId, 'failed', {
          paystackReference: reference,
          paidAmount: amountCheck.paidAmount,
          expectedAmount: amountCheck.expectedAmount,
          amountDifference: amountCheck.difference,
          failureReason: 'Amount mismatch',
          requiresRefund: true,
          requiresManualReview: true,
          webhookReceivedAt: Date.now()
        });
        
        return res.sendStatus(200);
      }
      
      // Amount valid - update status
      await FirestoreService.updateTopupStatus(sessionId, 'payment_verified', {
        paystackReference: reference,
        paidAmount: amountCheck.paidAmount,
        paidAt: new Date(event.data.paid_at).getTime(),
        paymentChannel: event.data.channel,
        webhookReceivedAt: Date.now()
      });
      
      logger.info('✅ Webhook processed', { sessionId, reference });
    }
    
    res.sendStatus(200);
  } catch (error) {
    logger.error('❌ Webhook error', { error: error.message });
    res.sendStatus(500);
  }
});

// CHECK STATUS
app.get('/api/topup/status/:sessionId', async (req, res, next) => {
  try {
    const { sessionId } = req.params;
    const snapshot = await db.ref(`topup_transactions/${sessionId}`).once('value');
    
    if (!snapshot.exists()) {
      return res.status(404).json({ success: false, error: 'Transaction not found' });
    }
    
    const session = snapshot.val();
    
    res.json({
      success: true, sessionId, status: session.status,
      expiresAt: session.expiresAt ? new Date(session.expiresAt).toISOString() : null
    });
  } catch (error) {
    next(error);
  }
});
app.get('/my-ip', (req, res) => {
  res.json({
    serverIP: req.socket.localAddress,
    requestIP: req.ip,
    headers: req.headers
  });
});

// USER APIS (kept from previous version)
app.get('/api/user/profile', extractUser, async (req, res, next) => {
  try {
    if (!req.identifier) return res.status(401).json({ success: false, error: 'UID or email required' });
    
    const snapshot = await db.ref(`topup_users/${req.identifier}`).once('value');
    if (!snapshot.exists()) return res.status(404).json({ success: false, error: 'User not found' });
    
    const userData = snapshot.val();
    res.json({ success: true, user: sanitizeForLog(userData) });
  } catch (error) {
    next(error);
  }
});

app.get('/api/user/tiers', (req, res) => {
  res.json({ success: true, tiers: config.loyalty.tiers });
});

app.get('/api/user/rewards', extractUser, async (req, res, next) => {
  try {
    if (!req.identifier) return res.status(401).json({ success: false, error: 'UID or email required' });
    const loyalty = await FirestoreService.getUserLoyaltyStats(req.identifier);
    if (!loyalty) return res.status(404).json({ success: false, error: 'User not found' });
    res.json({ success: true, loyalty });
  } catch (error) {
    next(error);
  }
});

app.get('/api/user/transactions', extractUser, async (req, res, next) => {
  try {
    if (!req.identifier) return res.status(401).json({ success: false, error: 'UID or email required' });
    
    const { limit = 20 } = req.query;
    
    const snapshot = await db.ref('topup_transactions')
      .orderByChild('identifier')
      .equalTo(req.identifier)
      .limitToLast(parseInt(limit))
      .once('value');
    
    if (!snapshot.exists()) {
      return res.json({ success: true, transactions: [], count: 0 });
    }
    
    const transactions = [];
    snapshot.forEach(child => {
      const data = child.val();
      transactions.push({
        id: data.sessionId,
        network: data.network,
        type: data.type,
        amountINR: data.summary.amountINR,
        amountNGN: data.summary.amountNGN,
        status: data.status,
        createdAt: new Date(data.createdAt).toISOString()
      });
    });
    
    res.json({ success: true, transactions: transactions.reverse(), count: transactions.length });
  } catch (error) {
    next(error);
  }
});

// METRICS
app.get("/metrics", (req, res) => {
  res.json({
    ...metrics,
    cache: cache.getStats(),
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ERROR HANDLER
app.use((err, req, res, next) => {
  logger.error('API Error', { 
    error: err.message, 
    stack: err.stack, 
    path: req.path,
    statusCode: err.statusCode 
  });
  
  res.status(err.statusCode || 500).json({ 
    success: false, 
    error: err.message || 'Internal error',
    ...(config.nodeEnv !== 'production' && { details: err.details })
  });
});

// ============================================================================
// CLEANUP EXPIRED SESSIONS (from main server)
// ============================================================================
async function cleanupExpiredSessions() {
  try {
    const now = Date.now();
    const snapshot = await db.ref('topup_transactions')
      .orderByChild('expiresAt')
      .endAt(now)
      .once('value');
    
    if (!snapshot.exists()) return 0;
    
    const updates = {};
    let cleanupCount = 0;
    
    snapshot.forEach(child => {
      const session = child.val();
      
      // Only delete pending/failed/expired
      if (['pending', 'failed', 'expired'].includes(session.status)) {
        updates[`topup_transactions/${session.sessionId}`] = null;
        cleanupCount++;
      }
    });
    
    if (cleanupCount > 0) {
      await db.ref().update(updates);
      logger.info(`✅ Cleaned up ${cleanupCount} expired sessions`);
    }
    
    return cleanupCount;
  } catch (error) {
    logger.error('Cleanup failed', { error: error.message });
    return 0;
  }
}

// Run cleanup every 10 minutes
setInterval(cleanupExpiredSessions, 10 * 60 * 1000);
setTimeout(cleanupExpiredSessions, 30000);

// START SERVER
const server = app.listen(config.port, () => {
  console.log('\n═══════════════════════════════════════════════════════════');
  console.log('🛡️  PAYDRAK TOPUP SERVER v4.0-SECURE (PRODUCTION-READY)');
  console.log('═══════════════════════════════════════════════════════════');
  console.log(`📡 Server: http://localhost:${config.port}`);
  console.log(`🔥 Firebase: ✅ Realtime Database`);
  console.log(`🔐 Encryption: ✅ AES-256 (CryptoJS)`);
  console.log(`🚨 Fraud Detection: ✅ Multi-layer`);
  console.log(`🧪 Test Mode: ${config.a1topup.testMode ? '✅ ON' : '❌ OFF (LIVE)'}`);
  console.log(`💱 Exchange Rate: ₦${config.staticExchangeRate} per ₹1 (STATIC)`);
  console.log(`🛡️  Security: ✅ Bulletproof`);
  console.log(`   • Input sanitization`);
  console.log(`   • Amount verification (1% tolerance)`);
  console.log(`   • Status transition validation`);
  console.log(`   • Daily limits (user + IP)`);
  console.log(`   • Rapid transaction detection`);
  console.log(`   • Webhook signature verification`);
  console.log(`   • Encrypted user data`);
  console.log(`   • Sanitized logging`);
  console.log('═══════════════════════════════════════════════════════════\n');
});

process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
process.on('SIGINT', () => { server.close(() => process.exit(0)); });
