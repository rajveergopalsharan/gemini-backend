const express = require('express');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');

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

// Existing AI flow ko abhi break nahi karna,
// isliye current body limit same rakha hai.
// AI security migration me ise baad me safely reduce karenge.
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ======================================================
// RATE LIMITERS
// ======================================================

const summarizeLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  message: { error: 'Please try again in one minute.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const deleteAccountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: {
    error: 'Too many account deletion attempts. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ======================================================
// AUTH HELPER
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

// ======================================================
// EXISTING AI SUMMARY ROUTE
// ======================================================

app.post('/summarize', summarizeLimiter, async (req, res) => {
  const clientToken = getBearerToken(req);

  if (!clientToken) {
    return res.status(403).json({
      error: 'Unauthorized request.',
    });
  }

  try {
    // Firebase token verify
    await admin.auth().verifyIdToken(clientToken);

    const { text, summaryType } = req.body;
    const apiKey = process.env.GEMINI_API_KEY;

    if (
      typeof text !== 'string' ||
      text.trim().isEmpty ||
      typeof summaryType !== 'string' ||
      summaryType.trim().isEmpty
    ) {
      return res.status(400).json({
        error: 'Invalid request.',
      });
    }

    if (!apiKey) {
      return res.status(500).json({
        error: 'AI service is unavailable.',
      });
    }

    const prompt =
      `Please provide a ${summaryType} for the following text:\n\n${text}`;

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
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

    const data = await response.json();

    if (!response.ok) {
      return res.status(500).json({
        error: 'AI service failed. Please try again.',
      });
    }

    const summary =
      data?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (typeof summary !== 'string' || summary.trim().length === 0) {
      return res.status(500).json({
        error: 'AI response was empty. Please try again.',
      });
    }

    return res.status(200).json({
      summary: summary,
    });
  } catch (_) {
    return res.status(403).json({
      error: 'Invalid authentication or request.',
    });
  }
});

// ======================================================
// SECURE ACCOUNT DELETION
// ======================================================

app.post(
  '/delete-account',
  deleteAccountLimiter,
  async (req, res) => {
    const clientToken = getBearerToken(req);

    if (!clientToken) {
      return res.status(401).json({
        error: 'Authentication required.',
      });
    }

    try {
      // true = revoked/disabled session bhi reject hoga
      const decodedToken =
        await admin.auth().verifyIdToken(clientToken, true);

      // IMPORTANT:
      // UID body/query se nahi liya ja raha.
      // Verified Firebase token hi user decide karega.
      const uid = decodedToken.uid;

      if (!uid) {
        return res.status(401).json({
          error: 'Invalid authentication.',
        });
      }

      // Sensitive action: recent Google/Firebase authentication required.
      // auth_time seconds me hota hai.
      const authTime = decodedToken.auth_time;
      const nowSeconds = Math.floor(Date.now() / 1000);

      if (
        typeof authTime !== 'number' ||
        nowSeconds - authTime > 5 * 60
      ) {
        return res.status(401).json({
          code: 'RECENT_LOGIN_REQUIRED',
          error: 'Please sign in again before deleting your account.',
        });
      }

      // --------------------------------------------------
      // 1. Delete all Firestore data under users/{uid}
      // including nested subcollections such as:
      // creditState, aiUsage, subscription, purchases, etc.
      // --------------------------------------------------

      const userRef = db.collection('users').doc(uid);

      await db.recursiveDelete(userRef);

      // --------------------------------------------------
      // 2. Delete old legacy AI daily-limit document
      // if one happens to exist.
      // --------------------------------------------------

      const oldDailyLimitRef =
        db.collection('ai_daily_limits').doc(uid);

      await oldDailyLimitRef.delete();

      // --------------------------------------------------
      // 3. Delete Firebase Authentication user LAST.
      //
      // Data pehle delete karte hain, Auth baad me.
      // Agar data deletion fail ho to user authenticated
      // rehkar safely retry kar sakta hai.
      // --------------------------------------------------

      await admin.auth().deleteUser(uid);

      return res.status(200).json({
        success: true,
        message: 'Account and associated data deleted successfully.',
      });
    } catch (error) {
      // Sensitive token/UID/document data logs me print nahi kar rahe.
      console.error(
        'Account deletion failed:',
        error?.code || error?.name || 'UNKNOWN_ERROR'
      );

      return res.status(500).json({
        success: false,
        error: 'Account deletion could not be completed. Please try again.',
      });
    }
  }
);

// ======================================================
// HEALTH CHECK
// ======================================================

app.get('/', (req, res) => {
  return res.status(200).json({
    service: 'Rajveon Docs Backend',
    status: 'running',
  });
});

// ======================================================
// SERVER
// ======================================================

const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(`Rajveon Docs backend running on port ${PORT}`);
});
