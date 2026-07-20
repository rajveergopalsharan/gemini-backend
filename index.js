const express = require('express');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit'); // 1. Naya package import kiya

// Firebase Admin Setup
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  })
});

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 2. RATE LIMITER RULE BANAYA
const summarizeLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute ka time
    max: 5, // 1 minute mein maximum 5 requests allow karega
    message: { error: "Please try agin in one minute" },
    standardHeaders: true, 
    legacyHeaders: false,
});

// 3. LIMITER KO ROUTE PAR LAGA DIYA
app.post('/summarize', summarizeLimiter, async (req, res) => {
    
    // Yahan se aapka pehle wala Token Checking aur Gemini ka code same rahega
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).json({ error: "Unauthorized request." });
    }

    const clientToken = authHeader.split('Bearer ')[1];

    try {
        const decodedToken = await admin.auth().verifyIdToken(clientToken);
        
        const { text, summaryType } = req.body; 
        const apiKey = process.env.GEMINI_API_KEY;

        const prompt = `Please provide a ${summaryType} for the following text:\n\n${text}`;

        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }]
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            return res.status(500).json({ error: "Error please try agin" });
        }

        const summary = data.candidates[0].content.parts[0].text;
        res.json({ summary: summary });

    } catch (error) {
        console.error("Server Error:", error);
        return res.status(403).json({ error: "Invalid PDF or Network error!" });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Network running on ${PORT}`));
