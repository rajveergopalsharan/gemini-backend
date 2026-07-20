const express = require('express');
const admin = require('firebase-admin');

// 1. Firebase Admin Setup (Render Environment Variables se)
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    // Render mein newlines (\n) kabhi-kabhi text ban jate hain, isliye replace() lagaya hai
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  })
});

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.post('/summarize', async (req, res) => {
    // 2. SECURITY GUARD: Token Checking
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.error("Token missing ya galat format mein hai!");
        return res.status(403).json({ error: "Bhaag yahan se! Unauthorized request." });
    }

    // "Bearer " ke baad wala asal token nikalna
    const clientToken = authHeader.split('Bearer ')[1];

    try {
        // Firebase se token verify karwana
        const decodedToken = await admin.auth().verifyIdToken(clientToken);
        console.log("Verified Asli User ID:", decodedToken.uid);
    } catch (error) {
        console.error("Token verification fail ho gayi:", error);
        return res.status(403).json({ error: "Invalid ya expired token!" });
    }

    // 3. MAIN GEMINI LOGIC (Agar Token Sahi Hai)
    const { text, summaryType } = req.body; 
    const apiKey = process.env.GEMINI_API_KEY;

    try {
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
            return res.status(500).json({ error: "Gemini API limit ya key issue" });
        }

        const summary = data.candidates[0].content.parts[0].text;
        res.json({ summary: summary });
    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({ error: "Something went wrong!" });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
