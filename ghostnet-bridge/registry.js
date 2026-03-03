const http = require('http');

const nodes = [
    "ws://localhost:8080",
    "ws://localhost:8081",
    "ws://localhost:8082"
];

http.createServer((req, res) => {
    // Add CORS headers so frontend can access
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET");

    if (req.url === "/nodes") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(nodes));
    } else {
        res.writeHead(404);
        res.end();
    }
}).listen(9000);

console.log("GhostNet Registry running on 9000");
