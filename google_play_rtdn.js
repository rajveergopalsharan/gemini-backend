const crypto = require('crypto');
const { google } = require('googleapis');

function registerGooglePlayRtdn({
  app,
  db,
  admin,
  packageName,
  getGooglePlayPublisherClient,
  subscriptionStateHasEntitlement,
}) {
  const expectedAudience =
    (process.env.GOOGLE_PLAY_RTDN_AUDIENCE || '').trim();

  const expectedPushServiceAccount =
    (
      process.env.GOOGLE_PLAY_RTDN_PUSH_SERVICE_ACCOUNT ||
      ''
    ).trim();

  const oidcClient = new google.auth.OAuth2();

  async function verifyPushAuthentication(req) {
    if (
      !expectedAudience ||
      !expectedPushServiceAccount
    ) {
      throw new Error('RTDN_SERVER_NOT_CONFIGURED');
    }

    const authHeader =
      typeof req.headers.authorization === 'string'
        ? req.headers.authorization.trim()
        : '';

    if (!authHeader.startsWith('Bearer ')) {
      throw new Error('RTDN_AUTH_REQUIRED');
    }

    const idToken =
      authHeader.substring(7).trim();

    if (!idToken) {
      throw new Error('RTDN_AUTH_REQUIRED');
    }

    const ticket =
      await oidcClient.verifyIdToken({
        idToken,
        audience: expectedAudience,
      });

    const payload = ticket.getPayload();

    if (!payload) {
      throw new Error('RTDN_INVALID_AUTH');
    }

    const email =
      typeof payload.email === 'string'
        ? payload.email.trim()
        : '';

    if (email !== expectedPushServiceAccount) {
      throw new Error('RTDN_INVALID_PRINCIPAL');
    }

    if (payload.email_verified !== true) {
      throw new Error('RTDN_EMAIL_NOT_VERIFIED');
    }

    return payload;
  }

  function decodeNotification(body) {
    const encodedData =
      typeof body?.message?.data === 'string'
        ? body.message.data.trim()
        : '';

    if (!encodedData) {
      throw new Error('RTDN_MESSAGE_DATA_MISSING');
    }

    let decodedText = '';

    try {
      decodedText = Buffer.from(
        encodedData,
        'base64',
      ).toString('utf8');
    } catch (_) {
      throw new Error('RTDN_INVALID_BASE64');
    }

    let notification;

    try {
      notification = JSON.parse(decodedText);
    } catch (_) {
      throw new Error('RTDN_INVALID_JSON');
    }

    if (
      !notification ||
      typeof notification !== 'object'
    ) {
      throw new Error('RTDN_INVALID_MESSAGE');
    }

    return notification;
  }

  function findMatchingLineItem({
    subscriptionData,
    expectedProductId,
  }) {
    const lineItems =
      Array.isArray(subscriptionData?.lineItems)
        ? subscriptionData.lineItems
        : [];

    const matchingItems =
      lineItems.filter(
        (item) =>
          item &&
          item.productId === expectedProductId &&
          typeof item.expiryTime === 'string',
      );

    if (matchingItems.length === 0) {
      throw new Error('RTDN_PRODUCT_ID_MISMATCH');
    }

    let selectedItem = null;
    let selectedExpiry = null;

    for (const item of matchingItems) {
      const expiryDate =
        new Date(item.expiryTime);

      if (
        Number.isNaN(
          expiryDate.getTime(),
        )
      ) {
        continue;
      }

      if (
        !selectedExpiry ||
        expiryDate.getTime() >
          selectedExpiry.getTime()
      ) {
        selectedItem = item;
        selectedExpiry = expiryDate;
      }
    }

    if (
      !selectedItem ||
      !selectedExpiry
    ) {
      throw new Error(
        'RTDN_INVALID_SUBSCRIPTION_EXPIRY',
      );
    }

    return {
      item: selectedItem,
      expiryDate: selectedExpiry,
    };
  }

  async function loadExistingPlanConfig(
    productId,
  ) {
    const snapshot = await db
      .collection('premium_plans')
      .where(
        'productId',
        '==',
        productId,
      )
      .limit(1)
      .get();

    if (snapshot.empty) {
      throw new Error('RTDN_UNKNOWN_PREMIUM_PRODUCT');
    }

    const doc = snapshot.docs[0];
    const data = doc.data() || {};

    const dailyCredits =
      Number(data.dailyCredits);

    const priceInr =
      Number(data.priceInr);

    const durationType =
      typeof data.durationType === 'string'
        ? data.durationType.trim()
        : '';

    if (
      !Number.isInteger(dailyCredits) ||
      dailyCredits <= 0 ||
      !Number.isInteger(priceInr) ||
      priceInr <= 0 ||
      (
        durationType !== 'monthly' &&
        durationType !== 'yearly'
      )
    ) {
      throw new Error('RTDN_INVALID_PREMIUM_PLAN');
    }

    return {
      id: doc.id,
      productId,
      title:
        typeof data.title === 'string'
          ? data.title.trim()
          : '',
      dailyCredits,
      priceInr,
      durationType,
    };
  }

  async function refreshSubscription(
    purchaseToken,
  ) {
    const cleanToken =
      typeof purchaseToken === 'string'
        ? purchaseToken.trim()
        : '';

    if (
      !cleanToken ||
      cleanToken.length > 5000
    ) {
      throw new Error('RTDN_INVALID_PURCHASE_TOKEN');
    }

    const tokenHash = crypto
      .createHash('sha256')
      .update(cleanToken)
      .digest('hex');

    const tokenRef = db
      .collection('googlePlayPurchaseTokens')
      .doc(tokenHash);

    const tokenSnapshot =
      await tokenRef.get();

    // RTDN can arrive before the app has completed
    // the first secure purchase verification.
    // Return a retryable error instead of guessing UID.
    if (!tokenSnapshot.exists) {
      throw new Error('RTDN_PURCHASE_TOKEN_NOT_LINKED');
    }

    const tokenData =
      tokenSnapshot.data() || {};

    const uid =
      typeof tokenData.uid === 'string'
        ? tokenData.uid.trim()
        : '';

    const expectedProductId =
      typeof tokenData.productId === 'string'
        ? tokenData.productId.trim()
        : '';

    if (!uid) {
      throw new Error('RTDN_TOKEN_OWNER_MISSING');
    }

    if (!expectedProductId) {
      throw new Error('RTDN_TOKEN_PRODUCT_MISSING');
    }

    const publisher =
      getGooglePlayPublisherClient();

    // Google Play Developer API is always the source
    // of truth. RTDN itself never grants Premium.
    const response = await publisher
      .purchases
      .subscriptionsv2
      .get({
        packageName,
        token: cleanToken,
      });

    const subscriptionData =
      response?.data || {};

    const subscriptionState =
      typeof subscriptionData.subscriptionState ===
      'string'
        ? subscriptionData.subscriptionState.trim()
        : '';

    if (!subscriptionState) {
      throw new Error(
        'RTDN_SUBSCRIPTION_STATE_MISSING',
      );
    }

    const verifiedLine =
      findMatchingLineItem({
        subscriptionData,
        expectedProductId,
      });

    const expiryDate =
      verifiedLine.expiryDate;

    const entitled =
      subscriptionStateHasEntitlement({
        subscriptionState,
        expiryDate,
      });

    const plan =
      await loadExistingPlanConfig(
        expectedProductId,
      );

    const subscriptionRef = db
      .collection('users')
      .doc(uid)
      .collection('subscription')
      .doc('current');

    const purchaseRef = db
      .collection('users')
      .doc(uid)
      .collection('purchases')
      .doc(tokenHash);

    let entitlementUpdated = false;

    await db.runTransaction(
      async (transaction) => {
        const currentSubscription =
          await transaction.get(
            subscriptionRef,
          );

        const currentData =
          currentSubscription.exists
            ? currentSubscription.data() || {}
            : {};

        const currentTokenHash =
          typeof currentData.purchaseTokenHash ===
          'string'
            ? currentData.purchaseTokenHash.trim()
            : '';

        // Keep token ledger fresh.
        transaction.set(
          tokenRef,
          {
            uid,
            productId: expectedProductId,
            packageName,
            tokenHash,
            updatedAt:
              admin.firestore
                .FieldValue
                .serverTimestamp(),
          },
          {
            merge: true,
          },
        );

        // Keep history for this exact purchase token.
        transaction.set(
          purchaseRef,
          {
            id: tokenHash,
            productId: expectedProductId,
            planId: plan.id,
            purchaseTokenHash: tokenHash,
            source: 'google_play',
            status:
              entitled
                ? 'active'
                : 'inactive',
            googleSubscriptionState:
              subscriptionState,
            priceInr: plan.priceInr,
            dailyCredits:
              plan.dailyCredits,
            expiryDate:
              admin.firestore
                .Timestamp
                .fromDate(
                  expiryDate,
                ),
            verifiedByServer: true,
            updatedAt:
              admin.firestore
                .FieldValue
                .serverTimestamp(),
          },
          {
            merge: true,
          },
        );

        // CRITICAL:
        // A late notification from an older token must
        // never overwrite/revoke a newer subscription.
        if (
          currentTokenHash &&
          currentTokenHash !== tokenHash
        ) {
          return;
        }

        transaction.set(
          subscriptionRef,
          {
            planId: plan.id,
            productId:
              expectedProductId,
            title: plan.title,
            dailyCredits:
              plan.dailyCredits,
            durationType:
              plan.durationType,
            status:
              entitled
                ? 'active'
                : 'inactive',
            source: 'google_play',
            verifiedByServer: true,
            purchaseTokenHash:
              tokenHash,
            googleSubscriptionState:
              subscriptionState,
            expiryDate:
              admin.firestore
                .Timestamp
                .fromDate(
                  expiryDate,
                ),
            updatedAt:
              admin.firestore
                .FieldValue
                .serverTimestamp(),
          },
          {
            merge: true,
          },
        );

        entitlementUpdated = true;
      },
    );

    return {
      uid,
      productId:
        expectedProductId,
      subscriptionState,
      entitled,
      expiryDate,
      entitlementUpdated,
    };
  }

  app.post(
    '/billing/google-play-rtdn',
    async (req, res) => {
      try {
        await verifyPushAuthentication(
          req,
        );

        const notification =
          decodeNotification(
            req.body,
          );

        const notificationPackageName =
          typeof notification.packageName ===
          'string'
            ? notification.packageName.trim()
            : '';

        if (
          notificationPackageName &&
          notificationPackageName !==
            packageName
        ) {
          throw new Error(
            'RTDN_PACKAGE_MISMATCH',
          );
        }

        // Google Play Console test message.
        if (notification.testNotification) {
          console.log(
            'Google Play RTDN test notification received.',
          );

          return res
            .status(204)
            .send();
        }

        const subscriptionNotification =
          notification.subscriptionNotification;

        const voidedPurchaseNotification =
          notification.voidedPurchaseNotification;

        let purchaseToken = '';
        let notificationType = '';

        if (
          subscriptionNotification &&
          typeof subscriptionNotification ===
            'object'
        ) {
          purchaseToken =
            typeof subscriptionNotification
              .purchaseToken === 'string'
              ? subscriptionNotification
                  .purchaseToken
                  .trim()
              : '';

          notificationType =
            String(
              subscriptionNotification
                .notificationType ?? '',
            );
        } else if (
          voidedPurchaseNotification &&
          typeof voidedPurchaseNotification ===
            'object'
        ) {
          purchaseToken =
            typeof voidedPurchaseNotification
              .purchaseToken === 'string'
              ? voidedPurchaseNotification
                  .purchaseToken
                  .trim()
              : '';

          notificationType =
            'voided_purchase';
        } else {
          // Unknown/irrelevant authenticated RTDN.
          return res
            .status(204)
            .send();
        }

        if (!purchaseToken) {
          throw new Error(
            'RTDN_PURCHASE_TOKEN_MISSING',
          );
        }

        const result =
          await refreshSubscription(
            purchaseToken,
          );

        console.log(
          'Google Play RTDN processed:',
          {
            messageId:
              req.body?.message?.messageId ||
              '',
            notificationType,
            productId:
              result.productId,
            subscriptionState:
              result.subscriptionState,
            entitled:
              result.entitled,
            entitlementUpdated:
              result.entitlementUpdated,
          },
        );

        return res
          .status(204)
          .send();
      } catch (error) {
        const message =
          error?.message || '';

        console.error(
          'Google Play RTDN error:',
          message ||
            'UNKNOWN_ERROR',
        );

        if (
          message ===
            'RTDN_AUTH_REQUIRED' ||
          message ===
            'RTDN_INVALID_AUTH' ||
          message ===
            'RTDN_INVALID_PRINCIPAL' ||
          message ===
            'RTDN_EMAIL_NOT_VERIFIED'
        ) {
          return res
            .status(401)
            .json({
              success: false,
            });
        }

        if (
          message ===
          'RTDN_SERVER_NOT_CONFIGURED'
        ) {
          return res
            .status(503)
            .json({
              success: false,
            });
        }

        // Race between Google notification and first
        // client verification: ask Pub/Sub to retry.
        if (
          message ===
          'RTDN_PURCHASE_TOKEN_NOT_LINKED'
        ) {
          return res
            .status(500)
            .json({
              success: false,
            });
        }

        // Authenticated but malformed/irrelevant event:
        // acknowledge it to avoid endless retries.
        if (
          message.startsWith('RTDN_')
        ) {
          return res
            .status(204)
            .send();
        }

        // Google API / Firestore temporary failures:
        // non-2xx makes Pub/Sub retry later.
        return res
          .status(500)
          .json({
            success: false,
          });
      }
    },
  );
}

module.exports = {
  registerGooglePlayRtdn,
};