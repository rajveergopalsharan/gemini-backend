const express = require('express');
const app = express();

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.post('/summarize', async (req, res) => {
    const { text, summaryType } = req.body; 
    const apiKey = process.env.GEMINI_API_KEY;

    try {
        const prompt = `Please provide a ${summaryType} for the following text:\n\n${text}`;

        // Yahan maine model ka naam badal kar 'gemini-1.5-flash-latest' kar diya hai
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }]
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            console.error("Gemini API Error:", data);
            return res.status(500).json({ error: "Gemini API limit ya key issue" });
        }

        const summary = data.candidates[0].content.parts[0].text;
        res.json({ summary: summary });
    } catch (error) {
        console.error("Mera Server Error:", error);
        res.status(500).json({ error: "Something went wrong!" });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
