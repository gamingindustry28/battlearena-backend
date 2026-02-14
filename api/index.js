// index.js - Production backend for esports tournament app
const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');

// Initialize Firebase Admin SDK
const serviceAccount = require('./serviceAccountKey.json'); // Must be provided separately

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://YOUR_PROJECT_ID.firebaseio.com" // Replace with actual
});

const db = admin.firestore();
const app = express();
app.use(express.json());

// Cashfree configuration (set via environment variables)
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID;
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CASHFREE_API_URL = process.env.CASHFREE_API_URL || 'https://api.cashfree.com/pg';
const CASHFREE_WEBHOOK_SECRET = process.env.CASHFREE_WEBHOOK_SECRET;

// Middleware to verify Firebase ID token
async function verifyAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const idToken = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Helper to generate referral code
function generateReferralCode(uid) {
  return uid.slice(-6).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase();
}

// POST /auth/signup
app.post('/auth/signup', async (req, res) => {
  try {
    const { uid, username, email, referralCode } = req.body;
    
    if (!uid || !username || !email) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const userRef = db.collection('users').doc(uid);
    const userDoc = await userRef.get();
    
    if (userDoc.exists) {
      return res.status(200).json({ message: 'User already exists' });
    }
    
    const newReferralCode = generateReferralCode(uid);
    const userData = {
      username,
      email,
      wallet: 0,
      totalXP: 0,
      joinedMatches: [],
      referralCode: newReferralCode,
      referredBy: referralCode || null,
      matchesPlayed: 0,
      totalKills: 0,
      dailyStreak: 0,
      isVIP: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      status: 'active'
    };
    
    await userRef.set(userData);
    
    // If referred, update referrer's record (but no wallet credit yet)
    if (referralCode) {
      const referrerQuery = await db.collection('users').where('referralCode', '==', referralCode).limit(1).get();
      if (!referrerQuery.empty) {
        const referrerDoc = referrerQuery.docs[0];
        await referrerDoc.ref.update({
          referrals: admin.firestore.FieldValue.arrayUnion(uid)
        });
      }
    }
    
    res.status(201).json({ message: 'User created', referralCode: newReferralCode });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /match/join - With transaction for money safety
app.post('/match/join', verifyAuth, async (req, res) => {
  const { matchId, gameUids } = req.body;
  const userId = req.user.uid;
  
  if (!matchId || !gameUids || !Array.isArray(gameUids) || ![1,2,4].includes(gameUids.length)) {
    return res.status(400).json({ error: 'Invalid request: gameUids must be array of length 1,2, or 4' });
  }
  
  try {
    await db.runTransaction(async (transaction) => {
      // Get match document
      const matchRef = db.collection('matches').doc(matchId);
      const matchDoc = await transaction.get(matchRef);
      
      if (!matchDoc.exists) {
        throw new Error('Match not found');
      }
      
      const match = matchDoc.data();
      
      // Validate match status
      if (match.status !== 'upcoming') {
        throw new Error('Match is not available for joining');
      }
      
      // Check slot availability
      if (match.joinedCount >= match.maxPlayers) {
        throw new Error('Match is full');
      }
      
      // Check if user already joined (via teams subcollection)
      const teamRef = db.collection('matches').doc(matchId).collection('teams').doc(userId);
      const teamDoc = await transaction.get(teamRef);
      if (teamDoc.exists) {
        throw new Error('You have already joined this match');
      }
      
      // Check if any gameUid already used in other teams
      const teamsSnapshot = await transaction.get(db.collection('matches').doc(matchId).collection('teams'));
      const allGameUids = new Set();
      teamsSnapshot.forEach(doc => {
        const team = doc.data();
        team.gameUids?.forEach(uid => allGameUids.add(uid));
      });
      
      for (const uid of gameUids) {
        if (allGameUids.has(uid)) {
          throw new Error(`Game UID ${uid} is already registered in another team`);
        }
      }
      
      // Check wallet balance
      const userRef = db.collection('users').doc(userId);
      const userDoc = await transaction.get(userRef);
      
      if (!userDoc.exists) {
        throw new Error('User not found');
      }
      
      const user = userDoc.data();
      if (user.wallet < match.entryFee) {
        throw new Error('Insufficient wallet balance');
      }
      
      // Deduct entry fee from wallet
      transaction.update(userRef, {
        wallet: admin.firestore.FieldValue.increment(-match.entryFee)
      });
      
      // Create team document
      transaction.set(teamRef, {
        ownerUid: userId,
        ownerUsername: user.username,
        gameUids: gameUids,
        joinedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Increment joinedCount in match
      transaction.update(matchRef, {
        joinedCount: admin.firestore.FieldValue.increment(1)
      });
      
      // Add to user's joined matches
      transaction.update(userRef, {
        joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
      });
      
      // Create transaction log
      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId,
        type: 'match_fee',
        amount: -match.entryFee,
        matchId,
        status: 'completed',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });
    
    res.json({ success: true, message: 'Successfully joined match' });
  } catch (error) {
    console.error('Join match error:', error);
    res.status(400).json({ error: error.message });
  }
});

// POST /wallet/createOrder - Cashfree order creation
app.post('/wallet/createOrder', verifyAuth, async (req, res) => {
  try {
    const { amount } = req.body;
    const userId = req.user.uid;
    
    if (!amount || amount < 1) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    
    // Generate unique order ID
    const orderId = `ORDER_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    
    // Store pending transaction in Firestore
    const txRef = db.collection('transactions').doc(orderId);
    await txRef.set({
      userId,
      amount,
      type: 'deposit',
      status: 'PENDING',
      orderId,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    // Create Cashfree order
    const cashfreePayload = {
      order_id: orderId,
      order_amount: amount,
      order_currency: 'INR',
      customer_details: {
        customer_id: userId,
        customer_email: req.user.email || 'customer@example.com',
        customer_phone: '9999999999' // Ideally from user profile
      },
      order_meta: {
        return_url: 'https://yourapp.com/payment/return'
      }
    };
    
    const cashfreeResponse = await fetch(`${CASHFREE_API_URL}/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-version': '2022-09-01',
        'x-client-id': CASHFREE_APP_ID,
        'x-client-secret': CASHFREE_SECRET_KEY
      },
      body: JSON.stringify(cashfreePayload)
    });
    
    if (!cashfreeResponse.ok) {
      throw new Error('Cashfree order creation failed');
    }
    
    const orderData = await cashfreeResponse.json();
    
    // Update transaction with payment session ID
    await txRef.update({
      paymentSessionId: orderData.payment_session_id
    });
    
    res.json({
      orderId,
      paymentSessionId: orderData.payment_session_id
    });
    
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Failed to create payment order' });
  }
});

// POST /webhook/cashfree - ONLY place wallet is credited
app.post('/webhook/cashfree', async (req, res) => {
  try {
    // Verify webhook signature
    const signature = req.headers['x-webhook-signature'];
    const rawBody = JSON.stringify(req.body);
    
    const expectedSignature = crypto
      .createHmac('sha256', CASHFREE_WEBHOOK_SECRET)
      .update(rawBody)
      .digest('hex');
    
    if (signature !== expectedSignature) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
    
    const { order_id, order_amount, order_status } = req.body;
    
    if (!order_id || !order_status) {
      return res.status(400).json({ error: 'Invalid webhook payload' });
    }
    
    // Use transaction to prevent double-credit
    await db.runTransaction(async (transaction) => {
      const txRef = db.collection('transactions').doc(order_id);
      const txDoc = await transaction.get(txRef);
      
      if (!txDoc.exists) {
        throw new Error('Transaction not found');
      }
      
      const tx = txDoc.data();
      
      // Idempotency check - already processed
      if (tx.status === 'SUCCESS' || tx.status === 'FAILED') {
        return;
      }
      
      if (order_status === 'SUCCESS') {
        // Credit wallet
        const userRef = db.collection('users').doc(tx.userId);
        transaction.update(userRef, {
          wallet: admin.firestore.FieldValue.increment(tx.amount)
        });
        
        // Update transaction status
        transaction.update(txRef, {
          status: 'SUCCESS',
          completedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      } else {
        // Update transaction as failed
        transaction.update(txRef, {
          status: 'FAILED',
          failedAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    });
    
    res.json({ received: true });
    
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// POST /rewards/daily
app.post('/rewards/daily', verifyAuth, async (req, res) => {
  try {
    const userId = req.user.uid;
    const userRef = db.collection('users').doc(userId);
    
    const result = await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      
      if (!userDoc.exists) {
        throw new Error('User not found');
      }
      
      const user = userDoc.data();
      const now = new Date();
      const lastClaim = user.lastDailyClaim ? user.lastDailyClaim.toDate() : null;
      
      // Check if already claimed today
      if (lastClaim) {
        const lastClaimDate = new Date(lastClaim);
        lastClaimDate.setHours(0,0,0,0);
        const today = new Date();
        today.setHours(0,0,0,0);
        
        if (lastClaimDate.getTime() === today.getTime()) {
          throw new Error('Daily reward already claimed today');
        }
        
        // Check if consecutive day for streak
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        
        if (lastClaimDate.getTime() === yesterday.getTime()) {
          // Consecutive day
          transaction.update(userRef, {
            dailyStreak: (user.dailyStreak || 0) + 1
          });
        } else {
          // Streak broken
          transaction.update(userRef, {
            dailyStreak: 1
          });
        }
      } else {
        transaction.update(userRef, {
          dailyStreak: 1
        });
      }
      
      // Base reward + streak bonus
      const baseReward = 100;
      const streakBonus = (user.dailyStreak || 0) * 10;
      const totalReward = baseReward + streakBonus;
      
      // Credit wallet
      transaction.update(userRef, {
        wallet: admin.firestore.FieldValue.increment(totalReward),
        lastDailyClaim: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Create transaction record
      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId,
        type: 'daily_reward',
        amount: totalReward,
        streak: (user.dailyStreak || 0) + 1,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
      
      return { reward: totalReward, streak: (user.dailyStreak || 0) + 1 };
    });
    
    res.json({ success: true, ...result });
    
  } catch (error) {
    console.error('Daily reward error:', error);
    res.status(400).json({ error: error.message });
  }
});

// POST /wallet/withdraw
app.post('/wallet/withdraw', verifyAuth, async (req, res) => {
  try {
    const { amount, upiId } = req.body;
    const userId = req.user.uid;
    
    if (!amount || amount < 50 || !upiId) {
      return res.status(400).json({ error: 'Invalid amount or UPI ID' });
    }
    
    await db.runTransaction(async (transaction) => {
      const userRef = db.collection('users').doc(userId);
      const userDoc = await transaction.get(userRef);
      
      if (!userDoc.exists) {
        throw new Error('User not found');
      }
      
      const user = userDoc.data();
      
      if (user.wallet < amount) {
        throw new Error('Insufficient balance');
      }
      
      // Deduct from wallet immediately
      transaction.update(userRef, {
        wallet: admin.firestore.FieldValue.increment(-amount)
      });
      
      // Create withdrawal request
      const withdrawRef = db.collection('withdrawRequests').doc();
      transaction.set(withdrawRef, {
        userId,
        amount,
        upiId,
        status: 'PENDING',
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Create transaction record
      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId,
        type: 'withdraw_request',
        amount: -amount,
        status: 'PENDING',
        withdrawRequestId: withdrawRef.id,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    });
    
    res.json({ success: true, message: 'Withdrawal request submitted' });
    
  } catch (error) {
    console.error('Withdraw error:', error);
    res.status(400).json({ error: error.message });
  }
});

// POST /admin/match/distribute - Admin only endpoint
app.post('/admin/match/distribute', verifyAuth, async (req, res) => {
  try {
    // Verify admin status
    const user = req.user;
    const userDoc = await db.collection('users').doc(user.uid).get();
    
    // Check custom claim or admin flag
    if (!user.admin && !userDoc.data()?.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { matchId, gameUid, rank, kills } = req.body;
    
    if (!matchId || !gameUid || !rank || kills === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const result = await db.runTransaction(async (transaction) => {
      // Get match
      const matchRef = db.collection('matches').doc(matchId);
      const matchDoc = await transaction.get(matchRef);
      
      if (!matchDoc.exists) {
        throw new Error('Match not found');
      }
      
      const match = matchDoc.data();
      
      // Check if already distributed
      if (match.prizeDistributed) {
        throw new Error('Prizes already distributed for this match');
      }
      
      // Find team containing this gameUid
      const teamsSnapshot = await transaction.get(
        db.collection('matches').doc(matchId).collection('teams')
      );
      
      let targetTeam = null;
      teamsSnapshot.forEach(doc => {
        const team = doc.data();
        if (team.gameUids && team.gameUids.includes(gameUid)) {
          targetTeam = { id: doc.id, ...team };
        }
      });
      
      if (!targetTeam) {
        throw new Error('No team found with that Game UID');
      }
      
      // Calculate prizes
      const rankPrize = match.rankPrizes?.[rank] || 0;
      const perKillTotal = (match.perKillRate || 0) * kills;
      const totalPrize = rankPrize + perKillTotal;
      
      // Credit user
      const userRef = db.collection('users').doc(targetTeam.ownerUid);
      transaction.update(userRef, {
        wallet: admin.firestore.FieldValue.increment(totalPrize),
        totalXP: admin.firestore.FieldValue.increment(100), // XP formula
        matchesPlayed: admin.firestore.FieldValue.increment(1),
        totalKills: admin.firestore.FieldValue.increment(kills)
      });
      
      // Store result
      const resultRef = db.collection('matches').doc(matchId).collection('results').doc(gameUid);
      transaction.set(resultRef, {
        gameUid,
        rank,
        kills,
        prize: totalPrize,
        rankPrize,
        perKillPrize: perKillTotal,
        ownerUid: targetTeam.ownerUid,
        distributedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Mark match as distributed
      transaction.update(matchRef, {
        prizeDistributed: true,
        distributedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Create transaction record
      const txRef = db.collection('transactions').doc();
      transaction.set(txRef, {
        userId: targetTeam.ownerUid,
        type: 'prize',
        amount: totalPrize,
        matchId,
        rank,
        kills,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
      
      return { ownerUid: targetTeam.ownerUid, prize: totalPrize };
    });
    
    res.json({ success: true, ...result });
    
  } catch (error) {
    console.error('Distribution error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
