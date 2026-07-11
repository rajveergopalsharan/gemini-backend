const express = require('express');
const app = express();
app.use(express.json());

// Jab aapka app request bhejege toh ye chalega
app.post('/summarize', async (req, res) => {
    const { text } = req.body; // App se aaya hua PDF ka text
    const apiKey = process.env.GEMINI_API_KEY; // Ye Render server se milegi

    try {
        // Direct Gemini API ko call karna hamare server ke andar se
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: "Please summarize this text: " + text }] }]
            })
        });

        const data = await response.json();
        const summary = data.candidates[0].content.parts[0].text;
        
        // App ko wapas summary bhej dena
        res.json({ summary: summary });
    } catch (error) {
        res.status(500).json({ error: "Something went wrong!" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));