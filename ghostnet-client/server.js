const express = require("express");

const app = express();

app.use(express.static(__dirname));

const PORT = process.env.PORT || process.env.GHOSTNET_CLIENT_PORT || 3000;

app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'ghostnet-client', uptime: process.uptime() });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`GhostNet Client running on port ${PORT}`);
});

// keep alive
setInterval(() => { }, 1000);
