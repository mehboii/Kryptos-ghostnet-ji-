const http = require("http");
const { ethers } = require("ethers");

const provider = new ethers.JsonRpcProvider("https://rpc.sepolia.org");

// PASTE YOUR PRIVATE KEY BETWEEN QUOTES
const PRIVATE_KEY = "0x183abcea375e248eff5de166377fbf13a81baef8746d2efcf5b476e232bacffd";

const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

console.log("Wallet address:", wallet.address);

const server = http.createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/broadcast") {
    let body = "";

    req.on("data", c => body += c);

    req.on("end", async () => {
      try {
        const { to, amount } = JSON.parse(body);

        if (!ethers.isAddress(to)) {
          res.writeHead(400);
          return res.end("Invalid address");
        }

        const tx = await wallet.sendTransaction({
          to,
          value: ethers.parseEther(amount)
        });

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ hash: tx.hash }));

      } catch (e) {
        res.writeHead(500);
        res.end(e.toString());
      }
    });
  } else {
    res.writeHead(404);
    res.end();
  }
});

server.listen(3000, () =>
  console.log("REAL GhostNet Bridge running on http://localhost:3000")
);
