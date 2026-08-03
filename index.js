const express = require('express');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// ======================================================
// FIREBASE ADMIN
// ======================================================

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  }),
});

const db = admin.firestore();

const app = express();

// ======================================================
// ADMOB REWARDED SSV SECURITY
// ======================================================

const ADMOB_REWARDED_AD_UNIT_ID =
  'ca-app-pub-9269597231385928/6505738136';

const ADMOB_REWARDED_AD_UNIT_SUFFIX =
  '6505738136';

const ADMOB_REWARD_ITEM =
  'AI Credit';

const ADMOB_PUBLIC_KEYS_URL =
  'https://www.gstatic.com/admob/reward/verifier-keys.json';

// Google rotates verification keys.
// Keep cache safely below Google's 24-hour maximum guidance.
const ADMOB_KEYS_CACHE_MS =
  12 * 60 * 60 * 1000;

let admobVerificationKeys =
  new Map();

let admobKeysLoadedAt = 0;

async function loadAdMobVerificationKeys({
  forceRefresh = false,
} = {}) {
  const now = Date.now();

  if (
    !forceRefresh &&
    admobVerificationKeys.size > 0 &&
    now - admobKeysLoadedAt <
      ADMOB_KEYS_CACHE_MS
  ) {
    return admobVerificationKeys;
  }

  const response =
    await fetch(
      ADMOB_PUBLIC_KEYS_URL
    );

  if (!response.ok) {
    throw new Error(
      'ADMOB_KEYS_UNAVAILABLE'
    );
  }

  const data =
    await response.json();

  if (
    !data ||
    !Array.isArray(data.keys)
  ) {
    throw new Error(
      'ADMOB_KEYS_INVALID'
    );
  }

  const freshKeys =
    new Map();

  for (const key of data.keys) {
    const keyId =
      String(key.keyId ?? '');

    const pem =
      typeof key.pem === 'string'
        ? key.pem
        : '';

    if (
      keyId &&
      pem.includes(
        'BEGIN PUBLIC KEY'
      )
    ) {
      freshKeys.set(
        keyId,
        pem
      );
    }
  }

  if (freshKeys.size === 0) {
    throw new Error(
      'ADMOB_KEYS_EMPTY'
    );
  }

  admobVerificationKeys =
    freshKeys;

  admobKeysLoadedAt =
    now;

  return admobVerificationKeys;
}

function decodeAdMobBase64Url(value) {
  const normalized =
    value
      .replace(/-/g, '+')
      .replace(/_/g, '/');

  const remainder =
    normalized.length % 4;

  const padded =
    remainder === 0
      ? normalized
      : normalized +
        '='.repeat(
          4 - remainder
        );

  return Buffer.from(
    padded,
    'base64'
  );
}

async function verifyAdMobSsvRequest(req) {
  const originalUrl =
    req.originalUrl;


  const questionIndex =
    originalUrl.indexOf('?');

  if (questionIndex < 0) {
    throw new Error(
      'SSV_QUERY_MISSING'
    );
  }

  // IMPORTANT:
  // Do not reconstruct/reorder query parameters.
  // Google's signature covers the exact original query
  // content before "&signature=".
  const rawQuery =
    originalUrl.substring(
      questionIndex + 1
    );

  const signatureMarker =
    '&signature=';

  const signatureIndex =
    rawQuery.lastIndexOf(
      signatureMarker
    );

  if (signatureIndex < 0) {
    throw new Error(
      'SSV_SIGNATURE_MISSING'
    );
  }

  const signedContent =
    rawQuery.substring(
      0,
      signatureIndex
    );

  const signatureSection =
    rawQuery.substring(
      signatureIndex +
        signatureMarker.length
    );

  const keyMarker =
    '&key_id=';

  const keyIndex =
    signatureSection.lastIndexOf(
      keyMarker
    );

  if (keyIndex < 0) {
    throw new Error(
      'SSV_KEY_ID_MISSING'
    );
  }

  const encodedSignature =
    signatureSection.substring(
      0,
      keyIndex
    );

  const encodedKeyId =
    signatureSection.substring(
      keyIndex +
        keyMarker.length
    );

  const signatureText =
    decodeURIComponent(
      encodedSignature
    );

  const keyId =
    decodeURIComponent(
      encodedKeyId
    );

  if (
    !signatureText ||
    !keyId
  ) {
    throw new Error(
      'SSV_SIGNATURE_INVALID'
    );
  }

  let keys =
    await loadAdMobVerificationKeys();

  if (!keys.has(keyId)) {
    keys =
      await loadAdMobVerificationKeys({
        forceRefresh: true,
      });
  }

  const publicKey =
    keys.get(keyId);

  if (!publicKey) {
    throw new Error(
      'SSV_KEY_NOT_FOUND'
    );
  }

  const signature =
    decodeAdMobBase64Url(
      signatureText
    );

  const verifier =
    crypto.createVerify(
      'SHA256'
    );

  // Google/Tink verifies the URI-decoded query content.
  // Example: AI%20Credit must be verified as "AI Credit".
  const decodedSignedContent =
    decodeURIComponent(
      signedContent
    );

  verifier.update(
    decodedSignedContent,
    'utf8'
  );

  verifier.end();

  const valid =
    verifier.verify(
      publicKey,
      signature
    );

  if (!valid) {
    throw new Error(
      'SSV_SIGNATURE_REJECTED'
    );
  }

  return true;
}

function isExpectedRewardedAdUnit(
  adUnit
) {
  if (
    typeof adUnit !== 'string' ||
    adUnit.trim().length === 0
  ) {
    return false;
  }

  const value =
    adUnit.trim();

  return (
    value ===
      ADMOB_REWARDED_AD_UNIT_ID ||
    value ===
      ADMOB_REWARDED_AD_UNIT_SUFFIX ||
    value.endsWith(
      '/' +
        ADMOB_REWARDED_AD_UNIT_SUFFIX
    )
  );
}

// 100-page PDF text ke liye enough,
// lekin abusive 50 MB requests allow nahi karenge.
app.use(express.json({ limit: '3mb' }));
app.use(express.urlencoded({ limit: '3mb', extended: true }));

// ======================================================
// CONSTANTS
// ======================================================

const MAX_TEXT_CHARS = 750000;

const ALLOWED_SUMMARY_TYPES = new Set([
  'Short Summary',
  'Detailed Summary',
  'Key Points',
  'Student Notes',
]);

// Server-owned daily reset.
// Device clock ko trust nahi kiya jayega.
//
// Abhi India timezone use kar rahe hain so reset
// midnight India time par deterministic rahega.
const DAILY_RESET_TIME_ZONE = 'Asia/Kolkata';

// ======================================================
// RATE LIMITERS
// ======================================================

const summarizeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: {
    error: 'Too many AI requests. Please try again in one minute.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const deleteAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: {
    error:
      'Too many account deletion attempts. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ======================================================
// AUTH HELPERS
// ======================================================

function getBearerToken(req) {
  const authHeader = req.headers.authorization;

  if (
    typeof authHeader !== 'string' ||
    !authHeader.startsWith('Bearer ')
  ) {
    return null;
  }

  const token = authHeader.substring(7).trim();

  return token.length > 0 ? token : null;
}

async function authenticateRequest(req) {
  const token = getBearerToken(req);

  if (!token) {
    const error = new Error('AUTH_REQUIRED');
    error.statusCode = 401;
    throw error;
  }

  try {
    return await admin.auth().verifyIdToken(token);
  } catch (_) {
    const error = new Error('INVALID_AUTH');
    error.statusCode = 401;
    throw error;
  }
}

// ======================================================
// SERVER DATE
// ======================================================

function getServerDateKey() {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: DAILY_RESET_TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });

  return formatter.format(new Date());
}

// ======================================================
// CONFIG
// ======================================================

function defaultCreditRules() {
  return [
    { minPages: 1, maxPages: 15, credits: 1 },
    { minPages: 16, maxPages: 35, credits: 2 },
    { minPages: 36, maxPages: 60, credits: 3 },
    { minPages: 61, maxPages: 100, credits: 6 },
  ];
}

function defaultRevenueConfig() {
  return {
    freeDailyCredits: 2,
    rewardedAdCreditValue: 1,
    premiumDailyCredits: 22,
    maxPdfPagesV1: 100,
    cachedSummaryCreditCost: 1,
    maintenanceMode: false,
    creditRules: defaultCreditRules(),
  };
}

function normalizePositiveInt(value, fallback) {
  const number = Number(value);

  if (!Number.isInteger(number) || number < 0) {
    return fallback;
  }

  return number;
}

function normalizeCreditRules(rawRules) {
  if (!Array.isArray(rawRules)) {
    return defaultCreditRules();
  }

  const normalized = rawRules
    .map((item) => {
      if (!item || typeof item !== 'object') return null;

      const minPages = Number(item.minPages);
      const maxPages = Number(item.maxPages);
      const credits = Number(item.credits);

      if (
        !Number.isInteger(minPages) ||
        !Number.isInteger(maxPages) ||
        !Number.isInteger(credits) ||
        minPages <= 0 ||
        maxPages < minPages ||
        credits <= 0
      ) {
        return null;
      }

      return {
        minPages,
        maxPages,
        credits,
      };
    })
    .filter(Boolean)
    .sort((a, b) => a.minPages - b.minPages);

  return normalized.length > 0
    ? normalized
    : defaultCreditRules();
}

async function loadRevenueConfig() {
  const fallback = defaultRevenueConfig();

  try {
    const snapshot = await db
      .collection('appConfig')
      .doc('revenue')
      .get();

    if (!snapshot.exists) {
      return fallback;
    }

    const data = snapshot.data() || {};

    return {
      freeDailyCredits: normalizePositiveInt(
        data.freeDailyCredits,
        fallback.freeDailyCredits
      ),

      rewardedAdCreditValue: normalizePositiveInt(
        data.rewardedAdCreditValue,
        fallback.rewardedAdCreditValue
      ),

      premiumDailyCredits: normalizePositiveInt(
        data.premiumDailyCredits,
        fallback.premiumDailyCredits
      ),

      maxPdfPagesV1: normalizePositiveInt(
        data.maxPdfPagesV1,
        fallback.maxPdfPagesV1
      ),

      cachedSummaryCreditCost: normalizePositiveInt(
        data.cachedSummaryCreditCost,
        fallback.cachedSummaryCreditCost
      ),

      maintenanceMode: data.maintenanceMode === true,

      creditRules: normalizeCreditRules(data.creditRules),
    };
  } catch (_) {
    return fallback;
  }
}

function calculateFreshSummaryCredits(config, pageCount) {
  for (const rule of config.creditRules) {
    if (
      pageCount >= rule.minPages &&
      pageCount <= rule.maxPages
    ) {
      return rule.credits;
    }
  }

  throw new Error('INVALID_PAGE_COUNT');
}

// ======================================================
// PREMIUM ENTITLEMENT
// ======================================================
async function loadServerVerifiedSubscription(uid) {
  const snapshot = await db
    .collection('users')
    .doc(uid)
    .collection('subscription')
    .doc('current')
    .get();

  if (!snapshot.exists) {
    return {
      active: false,
      dailyCredits: 0,
    };
  }

  const data = snapshot.data() || {};

  // Client-created subscription documents are NOT trusted.
  // Later Google Play backend verification will set:
  // verifiedByServer: true
  if (data.verifiedByServer !== true) {
    return {
      active: false,
      dailyCredits: 0,
    };
  }

  if (data.status !== 'active') {
    return {
      active: false,
      dailyCredits: 0,
    };
  }

  let expiryDate = null;

  if (
    data.expiryDate &&
    typeof data.expiryDate.toDate === 'function'
  ) {
    expiryDate = data.expiryDate.toDate();
  }

  // Rajveon Docs has NO lifetime subscription.
  // Every trusted premium entitlement MUST contain
  // a backend-verified expiry date.
  if (!expiryDate) {
    return {
      active: false,
      dailyCredits: 0,
    };
  }

  if (expiryDate.getTime() <= Date.now()) {
    return {
      active: false,
      dailyCredits: 0,
    };
  }

  const dailyCredits = Number(data.dailyCredits);

  if (
    !Number.isInteger(dailyCredits) ||
    dailyCredits <= 0
  ) {
    return {
      active: false,
      dailyCredits: 0,
    };
  }

  return {
    active: true,
    dailyCredits,
  };
}

// ======================================================
// CREDIT STATE
// ======================================================

function createFreeState(config, today) {
  return {
    baseCreditsToday: config.freeDailyCredits,
    adCreditsToday: 0,
    premiumCreditsToday: 0,
    usedCreditsToday: 0,
    rewardedAdsWatchedToday: 0,
    dailyLimitDate: today,
  };
}

function createPremiumState(premiumDailyCredits, today) {
  return {
    baseCreditsToday: 0,
    adCreditsToday: 0,
    premiumCreditsToday: premiumDailyCredits,
    usedCreditsToday: 0,
    rewardedAdsWatchedToday: 0,
    dailyLimitDate: today,
  };
}

function normalizeCreditState(data) {
  return {
    baseCreditsToday: normalizePositiveInt(
      data?.baseCreditsToday,
      0
    ),

    adCreditsToday: normalizePositiveInt(
      data?.adCreditsToday,
      0
    ),

    premiumCreditsToday: normalizePositiveInt(
      data?.premiumCreditsToday,
      0
    ),

    usedCreditsToday: normalizePositiveInt(
      data?.usedCreditsToday,
      0
    ),

    rewardedAdsWatchedToday: normalizePositiveInt(
      data?.rewardedAdsWatchedToday,
      0
    ),

    dailyLimitDate:
      typeof data?.dailyLimitDate === 'string'
        ? data.dailyLimitDate
        : '',
  };
}

function availableCredits(state, isPremium) {
  if (isPremium) {
    return Math.max(
      0,
      state.premiumCreditsToday -
        state.usedCreditsToday
    );
  }

  return Math.max(
    0,
    state.baseCreditsToday +
      state.adCreditsToday -
      state.usedCreditsToday
  );
}

async function getCurrentCreditState(uid) {
  const config = await loadRevenueConfig();
  const subscription =
    await loadServerVerifiedSubscription(uid);

  const today = getServerDateKey();

  const creditRef = db
    .collection('users')
    .doc(uid)
    .collection('creditState')
    .doc('current');

  let finalState;

  await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(creditRef);

    let state;

    if (!snapshot.exists) {
      state = subscription.active
        ? createPremiumState(
            subscription.dailyCredits,
            today
          )
        : createFreeState(config, today);
    } else {
      state = normalizeCreditState(snapshot.data());

      if (state.dailyLimitDate !== today) {
        state = subscription.active
          ? createPremiumState(
              subscription.dailyCredits,
              today
            )
          : createFreeState(config, today);
      } else if (subscription.active) {
        state.premiumCreditsToday =
          subscription.dailyCredits;
        state.baseCreditsToday = 0;
      }
    }

    transaction.set(
      creditRef,
      {
        ...state,
        updatedAt:
          admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    finalState = state;
  });

  return {
    isPremium: subscription.active,
    state: finalState,
    availableCredits: availableCredits(
      finalState,
      subscription.active
    ),
  };
}

// ======================================================
// ATOMIC CREDIT RESERVATION
// ======================================================

async function reserveCredits({
  uid,
  requiredCredits,
  config,
}) {
  const subscription =
    await loadServerVerifiedSubscription(uid);

  const today = getServerDateKey();

  const creditRef = db
    .collection('users')
    .doc(uid)
    .collection('creditState')
    .doc('current');

  let result = null;

  await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(creditRef);

    let state;

    if (!snapshot.exists) {
      state = subscription.active
        ? createPremiumState(
            subscription.dailyCredits,
            today
          )
        : createFreeState(config, today);
    } else {
      state = normalizeCreditState(snapshot.data());

      if (state.dailyLimitDate !== today) {
        state = subscription.active
          ? createPremiumState(
              subscription.dailyCredits,
              today
            )
          : createFreeState(config, today);
      } else if (subscription.active) {
        state.premiumCreditsToday =
          subscription.dailyCredits;
        state.baseCreditsToday = 0;
      }
    }

    const before = availableCredits(
      state,
      subscription.active
    );

    if (before < requiredCredits) {
      transaction.set(
        creditRef,
        {
          ...state,
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      result = {
        allowed: false,
        isPremium: subscription.active,
        availableCredits: before,
      };

      return;
    }

    state.usedCreditsToday += requiredCredits;

    const after = availableCredits(
      state,
      subscription.active
    );

    transaction.set(
      creditRef,
      {
        ...state,
        updatedAt:
          admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    result = {
      allowed: true,
      isPremium: subscription.active,
      availableCredits: after,
    };
  });

  return result;
}

// ======================================================
// VERIFIED ADMOB REWARD CREDIT
//
// NO daily rewarded-ad limit.
// Each unique verified AdMob transaction = exactly +1 credit.
// Duplicate transaction IDs never grant another credit.
// ======================================================

async function grantVerifiedAdMobReward({
  uid,
  transactionId,
  adUnit,
  rewardAmount,
  rewardItem,
}) {
  const config =
    await loadRevenueConfig();

  if (
    config.rewardedAdCreditValue !== 1
  ) {
    throw new Error(
      'INVALID_REWARDED_AD_CONFIG'
    );
  }

  if (
    !isExpectedRewardedAdUnit(
      adUnit
    )
  ) {
    throw new Error(
      'WRONG_AD_UNIT'
    );
  }

  if (rewardAmount !== 1) {
    throw new Error(
      'WRONG_REWARD_AMOUNT'
    );
  }

  if (
    rewardItem !==
    ADMOB_REWARD_ITEM
  ) {
    throw new Error(
      'WRONG_REWARD_ITEM'
    );
  }

  const today =
    getServerDateKey();

  const creditRef = db
    .collection('users')
    .doc(uid)
    .collection('creditState')
    .doc('current');

  // Global transaction ledger.
  // Firestore client rules do not grant access to this collection.
  const rewardRef = db
    .collection(
      'admobRewardTransactions'
    )
    .doc(transactionId);

  let duplicate = false;

  await db.runTransaction(
    async (transaction) => {
      // All reads happen before writes.
      const rewardSnapshot =
        await transaction.get(
          rewardRef
        );

      const creditSnapshot =
        await transaction.get(
          creditRef
        );

      if (
        rewardSnapshot.exists
      ) {
        duplicate = true;
        return;
      }

      let state;

      if (
        !creditSnapshot.exists
      ) {
        state =
          createFreeState(
            config,
            today
          );
      } else {
        state =
          normalizeCreditState(
            creditSnapshot.data()
          );

        if (
          state.dailyLimitDate !==
          today
        ) {
          state =
            createFreeState(
              config,
              today
            );
        }
      }

      state.adCreditsToday +=
        1;

      state.rewardedAdsWatchedToday +=
        1;

      transaction.set(
        creditRef,
        {
          ...state,
          updatedAt:
            admin.firestore
              .FieldValue
              .serverTimestamp(),
        },
        { merge: true }
      );

      transaction.create(
        rewardRef,
        {
          uid,
          transactionId,
          adUnit,
          rewardAmount,
          rewardItem,
          creditsGranted: 1,
          createdAt:
            admin.firestore
              .FieldValue
              .serverTimestamp(),
        }
      );
    }
  );

  return {
    duplicate,
  };
}

// ======================================================
// REFUND
// ======================================================

async function refundCredits({
  uid,
  credits,
}) {
  if (!Number.isInteger(credits) || credits <= 0) {
    return;
  }

  const creditRef = db
    .collection('users')
    .doc(uid)
    .collection('creditState')
    .doc('current');

  await db.runTransaction(async (transaction) => {
    const snapshot = await transaction.get(creditRef);

    if (!snapshot.exists) {
      return;
    }

    const state = normalizeCreditState(
      snapshot.data()
    );

    state.usedCreditsToday = Math.max(
      0,
      state.usedCreditsToday - credits
    );

    transaction.set(
      creditRef,
      {
        ...state,
        updatedAt:
          admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  });
}

// ======================================================
// USAGE LOG
// ======================================================

async function saveAiUsage({
  uid,
  pdfName,
  pdfHash,
  pageCount,
  creditsCharged,
  summaryType,
  fromCache = false,
}) {
  const safeName =
    typeof pdfName === 'string'
      ? pdfName.substring(0, 250)
      : '';

  const safeHash =
    typeof pdfHash === 'string'
      ? pdfHash.substring(0, 500)
      : '';

  await db
    .collection('users')
    .doc(uid)
    .collection('aiUsage')
    .add({
      pdfName: safeName,
      pdfHash: safeHash,
      pageCount,
      creditsCharged,
      fromCache: fromCache === true,
      summaryType,
      createdAt:
        admin.firestore.FieldValue.serverTimestamp(),
    });
}

// ======================================================
// CREDIT INFO ENDPOINT
// ======================================================
app.get('/credits', async (req, res) => {
  try {
    const decodedToken =
      await authenticateRequest(req);

    const creditInfo =
      await getCurrentCreditState(
        decodedToken.uid
      );

    return res.status(200).json({
      success: true,
      isPremium: creditInfo.isPremium,
      availableCredits:
        creditInfo.availableCredits,
    });
  } catch (error) {
    return res
      .status(error.statusCode || 500)
      .json({
        success: false,
        error:
          error.message === 'AUTH_REQUIRED' ||
          error.message === 'INVALID_AUTH'
            ? 'Authentication required.'
            : 'Unable to load credits.',
      });
  }
});

// ======================================================
// SECURE CACHED-SUMMARY CREDIT ENDPOINT
//
// Cached summary text device par hi rehta hai.
// Server sirf configured cached-summary credit cost
// securely charge karta hai.
// Client kabhi credit amount decide nahi karega.
// ======================================================

app.post(
  '/consume-cached-summary',
  summarizeLimiter,
  async (req, res) => {
    let uid = null;
    let reservedCredits = 0;

    try {
      const decodedToken =
        await authenticateRequest(req);

      uid = decodedToken.uid;

      const {
        summaryType,
        pageCount,
        pdfName,
        pdfHash,
      } = req.body || {};

      // -------------------------------
      // INPUT VALIDATION
      // -------------------------------

      if (
        typeof summaryType !== 'string' ||
        !ALLOWED_SUMMARY_TYPES.has(summaryType)
      ) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_SUMMARY_TYPE',
          error: 'Invalid summary type.',
        });
      }

      const parsedPageCount =
        Number(pageCount);

      if (
        !Number.isInteger(parsedPageCount) ||
        parsedPageCount <= 0
      ) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_PAGE_COUNT',
          error: 'Invalid PDF page count.',
        });
      }

      // -------------------------------
      // CONFIG
      // -------------------------------

      const config =
        await loadRevenueConfig();

      if (config.maintenanceMode) {
        return res.status(503).json({
          success: false,
          code: 'MAINTENANCE',
          error:
            'AI service is temporarily unavailable.',
        });
      }

      if (
        parsedPageCount >
        config.maxPdfPagesV1
      ) {
        return res.status(400).json({
          success: false,
          code: 'PDF_TOO_LARGE',
          error:
            'This PDF is too large for AI Summary in V1.',
        });
      }

      // Server trusted Firestore config se
      // cached summary cost khud read karta hai.
      const requiredCredits =
        config.cachedSummaryCreditCost;

      if (
        !Number.isInteger(requiredCredits) ||
        requiredCredits <= 0
      ) {
        throw new Error(
          'INVALID_CACHED_SUMMARY_COST'
        );
      }

      // -------------------------------
      // ATOMIC SERVER CREDIT CHARGE
      // -------------------------------

      const reservation =
        await reserveCredits({
          uid,
          requiredCredits,
          config,
        });

      if (!reservation.allowed) {
        return res.status(402).json({
          success: false,
          code: 'NOT_ENOUGH_CREDITS',
          error: reservation.isPremium
            ? 'Daily premium AI limit reached.'
            : 'Not enough AI credits.',
          requiredCredits,
          availableCredits:
            reservation.availableCredits,
          isPremium:
            reservation.isPremium,
        });
      }

      reservedCredits =
        requiredCredits;

      // -------------------------------
      // USAGE LOG
      // -------------------------------

      await saveAiUsage({
        uid,
        pdfName,
        pdfHash,
        pageCount: parsedPageCount,
        creditsCharged:
          requiredCredits,
        summaryType,
        fromCache: true,
      });

      const currentCredits =
        await getCurrentCreditState(uid);

      return res.status(200).json({
        success: true,
        creditsCharged:
          requiredCredits,
        availableCredits:
          currentCredits.availableCredits,
        isPremium:
          currentCredits.isPremium,
      });
    } catch (error) {
      // Usage logging/backend failure ke case me
      // reserved credit wapas kar denge.
      if (
        uid &&
        reservedCredits > 0
      ) {
        try {
          await refundCredits({
            uid,
            credits:
              reservedCredits,
          });
        } catch (_) {}
      }

      if (
        error.statusCode === 401
      ) {
        return res.status(401).json({
          success: false,
          error:
            'Authentication required.',
        });
      }

      console.error(
        'Cached summary credit error:',
        error?.message ||
          'UNKNOWN_ERROR'
      );

      return res.status(500).json({
        success: false,
        error:
          'Cached summary could not be authorised. Your credits were not charged.',
      });
    }
  }
);

// ======================================================
// NEW SECURE AI SUMMARY ROUTE
// ======================================================

app.post(
  '/summarize-secure',
  summarizeLimiter,
  async (req, res) => {
    let uid = null;
    let reservedCredits = 0;

    try {
      const decodedToken =
        await authenticateRequest(req);

      uid = decodedToken.uid;

      const {
        text,
        summaryType,
        pageCount,
        pdfName,
        pdfHash,
      } = req.body || {};

      // -------------------------------
      // INPUT VALIDATION
      // -------------------------------

      if (
        typeof text !== 'string' ||
        text.trim().length === 0
      ) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_TEXT',
          error: 'PDF text is missing.',
        });
      }

      if (text.length > MAX_TEXT_CHARS) {
        return res.status(413).json({
          success: false,
          code: 'PDF_TOO_LARGE',
          error:
            'This PDF is too large for AI Summary.',
        });
      }

      if (
        typeof summaryType !== 'string' ||
        !ALLOWED_SUMMARY_TYPES.has(
          summaryType
        )
      ) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_SUMMARY_TYPE',
          error: 'Invalid summary type.',
        });
      }

      const parsedPageCount =
        Number(pageCount);

      if (
        !Number.isInteger(parsedPageCount) ||
        parsedPageCount <= 0
      ) {
        return res.status(400).json({
          success: false,
          code: 'INVALID_PAGE_COUNT',
          error: 'Invalid PDF page count.',
        });
      }

      // -------------------------------
      // CONFIG
      // -------------------------------

      const config =
        await loadRevenueConfig();

      if (config.maintenanceMode) {
        return res.status(503).json({
          success: false,
          code: 'MAINTENANCE',
          error:
            'AI service is temporarily unavailable.',
        });
      }

      if (
        parsedPageCount >
        config.maxPdfPagesV1
      ) {
        return res.status(400).json({
          success: false,
          code: 'PDF_TOO_LARGE',
          error:
            'This PDF is too large for AI Summary in V1.',
        });
      }

      // -------------------------------
      // SERVER CALCULATES COST
      // -------------------------------

      const requiredCredits =
        calculateFreshSummaryCredits(
          config,
          parsedPageCount
        );

      // -------------------------------
      // ATOMIC SERVER RESERVATION
      // -------------------------------

      const reservation =
        await reserveCredits({
          uid,
          requiredCredits,
          config,
        });

      if (!reservation.allowed) {
        return res.status(402).json({
          success: false,
          code: 'NOT_ENOUGH_CREDITS',
          error: reservation.isPremium
            ? 'Daily premium AI limit reached.'
            : 'Not enough AI credits.',
          requiredCredits,
          availableCredits:
            reservation.availableCredits,
          isPremium:
            reservation.isPremium,
        });
      }

      reservedCredits =
        requiredCredits;

      // -------------------------------
      // GEMINI
      // -------------------------------

      const apiKey =
        process.env.GEMINI_API_KEY;

      if (!apiKey) {
        throw new Error(
          'AI_SERVICE_UNAVAILABLE'
        );
      }

      const prompt =
        `Please provide a ${summaryType} ` +
        `for the following text:\n\n${text}`;

      const geminiController =
        new AbortController();

      const timeout = setTimeout(
        () => geminiController.abort(),
        60 * 1000
      );

      let geminiResponse;

      try {
        geminiResponse = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
          {
            method: 'POST',
            signal:
              geminiController.signal,
            headers: {
              'Content-Type':
                'application/json',
            },
            body: JSON.stringify({
              contents: [
                {
                  parts: [
                    {
                      text: prompt,
                    },
                  ],
                },
              ],
            }),
          }
        );
      } finally {
        clearTimeout(timeout);
      }

      const data =
        await geminiResponse.json();

      if (!geminiResponse.ok) {
        throw new Error(
          'GEMINI_REQUEST_FAILED'
        );
      }

      const summary =
        data?.candidates?.[0]?.content
          ?.parts?.[0]?.text;

      if (
        typeof summary !== 'string' ||
        summary.trim().length === 0
      ) {
        throw new Error(
          'EMPTY_AI_RESPONSE'
        );
      }

      // -------------------------------
      // USAGE LOG
      // -------------------------------

      await saveAiUsage({
        uid,
        pdfName,
        pdfHash,
        pageCount: parsedPageCount,
        creditsCharged:
          requiredCredits,
        summaryType,
        fromCache: false,
      });

      const currentCredits =
        await getCurrentCreditState(uid);

      return res.status(200).json({
        success: true,
        summary: summary.trim(),
        creditsCharged:
          requiredCredits,
        availableCredits:
          currentCredits.availableCredits,
        isPremium:
          currentCredits.isPremium,
      });
    } catch (error) {
      if (
        uid &&
        reservedCredits > 0
      ) {
        try {
          await refundCredits({
            uid,
            credits:
              reservedCredits,
          });
        } catch (_) {}
      }

      if (
        error.name === 'AbortError'
      ) {
        return res.status(504).json({
          success: false,
          error:
            'AI request timed out. Your credits were not charged.',
        });
      }

      if (
        error.statusCode === 401
      ) {
        return res.status(401).json({
          success: false,
          error:
            'Authentication required.',
        });
      }

      console.error(
        'Secure AI error:',
        error?.message ||
          'UNKNOWN_ERROR'
      );

      return res.status(500).json({
        success: false,
        error:
          'AI summary could not be generated. Your credits were not charged.',
      });
    }
  }
);
// ======================================================
// ADMOB REWARDED SSV CALLBACK
//
// This endpoint is called by Google AdMob, NOT by Flutter.
// Client callbacks alone can never grant credits.
// ======================================================

app.get(
  '/admob/rewarded-ssv',
  async (req, res) => {
    try {
      // First verify Google's cryptographic signature.
      await verifyAdMobSsvRequest(
        req
      );

      const userId =
        typeof req.query.user_id ===
        'string'
          ? req.query.user_id.trim()
          : '';

      const transactionId =
        typeof req.query.transaction_id ===
        'string'
          ? req.query.transaction_id.trim()
          : '';

      const adUnit =
        typeof req.query.ad_unit ===
        'string'
          ? req.query.ad_unit.trim()
          : '';

      const rewardItem =
        typeof req.query.reward_item ===
        'string'
          ? req.query.reward_item
          : '';

      const rewardAmount =
        Number(
          req.query.reward_amount
        );

      if (
        !transactionId ||
        !adUnit ||
        !Number.isInteger(
          rewardAmount
        )
      ) {
        return res
          .status(400)
          .send(
            'Invalid SSV request'
          );
      }

      // AdMob's URL verification test may omit user_id.
      // The request is already cryptographically verified,
      // so return HTTP 200 but NEVER grant a credit.
      if (!userId) {
        return res
          .status(200)
          .send(
            'SSV callback URL verified'
          );
      }

      // The SSV user_id must correspond to an
      // actual Firebase Authentication account.
      try {
        await admin
          .auth()
          .getUser(userId);
      } catch (error) {
        if (
          error?.code ===
          'auth/user-not-found'
        ) {
          // User was deleted after watching the ad.
          // Return 200 so Google does not keep retrying.
          return res
            .status(200)
            .send(
              'User no longer exists'
            );
        }

        throw error;
      }

      const result =
        await grantVerifiedAdMobReward({
          uid: userId,
          transactionId,
          adUnit,
          rewardAmount,
          rewardItem,
        });

      // Google may retry callbacks.
      // Duplicate transaction IDs still return HTTP 200,
      // but no second credit is granted.
      return res
        .status(200)
        .send(
          result.duplicate
            ? 'Already processed'
            : 'Reward verified'
        );
    } catch (error) {
      console.error(
        'AdMob SSV rejected:',
        error?.message ||
          'UNKNOWN_ERROR'
      );

      return res
        .status(400)
        .send(
          'Invalid SSV request'
        );
    }
  }
);

// ======================================================
// SECURE ACCOUNT DELETION
// ======================================================

app.post(
  '/delete-account',
  deleteAccountLimiter,
  async (req, res) => {
    const clientToken =
      getBearerToken(req);

    if (!clientToken) {
      return res.status(401).json({
        error:
          'Authentication required.',
      });
    }

    try {
      const decodedToken =
        await admin
          .auth()
          .verifyIdToken(
            clientToken,
            true
          );

      const uid =
        decodedToken.uid;

      if (!uid) {
        return res.status(401).json({
          error:
            'Invalid authentication.',
        });
      }

      const authTime =
        decodedToken.auth_time;

      const nowSeconds =
        Math.floor(Date.now() / 1000);

      if (
        typeof authTime !== 'number' ||
        nowSeconds - authTime >
          5 * 60
      ) {
        return res.status(401).json({
          code:
            'RECENT_LOGIN_REQUIRED',
          error:
            'Please sign in again before deleting your account.',
        });
      }

      const userRef = db
        .collection('users')
        .doc(uid);

      await db.recursiveDelete(
        userRef
      );

      await db
        .collection(
          'ai_daily_limits'
        )
        .doc(uid)
        .delete();

      await admin
        .auth()
        .deleteUser(uid);

      return res.status(200).json({
        success: true,
        message:
          'Account and associated data deleted successfully.',
      });
    } catch (error) {
      console.error(
        'Account deletion failed:',
        error?.code ||
          error?.name ||
          'UNKNOWN_ERROR'
      );

      return res.status(500).json({
        success: false,
        error:
          'Account deletion could not be completed. Please try again.',
      });
    }
  }
);

// ======================================================
// HEALTH CHECK
// ======================================================

app.get('/', (req, res) => {
  return res.status(200).json({
    service:
      'Rajveon Docs Backend',
    status: 'running',
  });
});

// ======================================================
// SERVER
// ======================================================

const PORT =
  process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(
    `Rajveon Docs backend running on port ${PORT}`
  );
});
