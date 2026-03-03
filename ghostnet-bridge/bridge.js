require("dotenv").config();
const http = require("http");
const { ethers } = require("ethers");
const { spawn } = require("child_process");
const { getBtcBalance, getNewAddress, btcRpc } = require("./btc-rpc");

// --- CONFIGURATION ---
const PORT = 3001;
const ETH_RPC_URL = "http://127.0.0.1:8545";
const PRIVATE_KEY = process.env.ETH_PRIVATE_KEY;
const SOL_ADDRESS = process.env.SOL_ADDRESS || "Solana_Address_Not_Set";

// --- STATE ---
let ethProvider = null;
let ethWallet = null;
let isEthOnline = false;
let hardhatProcess = null;

// --- UTILITIES ---
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// --- ETHEREUM ORCHESTRATION ---
async function startEthSystem() {
    console.log("🔵 ETH: Initializing subsystem...");

    // 1. Check if Node is already running
    const isRunning = await checkEthRpc();

    if (isRunning) {
        console.log("🔵 ETH: Node detected at 8545. Connecting...");
        await connectEthProvider();
    } else {
        console.log("🔵 ETH: RPC missing. Please start Hardhat manually.");
        // spawnHardhatNode(); // Disabled per user request
    }
}

function spawnHardhatNode() {
    const cmd = process.platform === 'win32' ? 'npx.cmd' : 'npx';
    const args = ['hardhat', 'node']; // Explicit network not needed as default is hardhat

    console.log(`> Spawning: ${cmd} ${args.join(' ')}`);

    try {
        hardhatProcess = spawn(cmd, args, {
            cwd: __dirname,
            stdio: 'pipe' // Capture output to detect readiness
        });

        hardhatProcess.stdout.on('data', (data) => {
            const line = data.toString();
            // console.log(`[Hardhat]: ${line.trim()}`); // Optional verbose logging
            if (line.includes("Started HTTP and WebSocket JSON-RPC server")) {
                console.log("✅ ETH: Local Node Started Successfully!");
                connectEthProvider();
            }
        });

        hardhatProcess.stderr.on('data', (data) => {
            console.error(`[Hardhat Error]: ${data}`);
        });

        hardhatProcess.on('close', (code) => {
            console.warn(`⚠️ ETH: Hardhat node exited with code ${code}`);
            isEthOnline = false;
            ethWallet = null;
            // Optional: Restart logic could go here
        });

    } catch (e) {
        console.error("❌ ETH: Failed to spawn Hardhat node. Is 'hardhat' installed?");
        console.error(e.message);
    }
}

async function checkEthRpc() {
    try {
        // Quick fetch to see if it responds
        const response = await fetch(ETH_RPC_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jsonrpc: "2.0", method: "eth_chainId", params: [], id: 1 })
        });
        return response.ok;
    } catch (e) {
        return false;
    }
}

async function connectEthProvider() {
    let attempts = 0;
    while (attempts < 5) {
        try {
            const provider = new ethers.JsonRpcProvider(ETH_RPC_URL, undefined, { staticNetwork: true });

            // Health handshake
            const net = await provider.getNetwork();

            ethProvider = provider;
            if (PRIVATE_KEY) {
                ethWallet = new ethers.Wallet(PRIVATE_KEY, ethProvider);
                console.log(`   🔑 Wallet loaded: ${ethWallet.address}`);
            } else {
                // Determine a default mock account from Hardhat (usually Account #0)
                // For simplified dev, we just warn.
                console.warn("   ⚠️ No PRIVATE_KEY in .env. Read-only mode.");
            }

            console.log(`✅ ETH: Fully Connected (Chain ID: ${net.chainId})`);
            isEthOnline = true;
            return;
        } catch (e) {
            attempts++;
            console.log(`   ... waiting for RPC (attempt ${attempts}/5)`);
            await sleep(2000);
        }
    }
    console.error("❌ ETH: Connection Timed Out. Node might be stuck.");
}

async function getSafeEthBalance() {
    if (!isEthOnline || !ethWallet) return "0.0000";
    try {
        const bal = await ethWallet.provider.getBalance(ethWallet.address);
        return ethers.formatEther(bal);
    } catch (e) {
        // Silent fail to prevent log spam if node temporarily flickers
        return "0.0000";
    }
}

// --- BOOT SEQUENCE ---
startEthSystem();


// --- HTTP API ---
const server = http.createServer(async (req, res) => {
    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") return res.writeHead(204).end();

    // GET /wallet
    if (req.url === "/wallet" && req.method === "GET") {
        try {
            // Parallel Fetch - BTC and ETH isolated
            const [ethBal, btcBal, btcAddr] = await Promise.all([
                getSafeEthBalance(),
                getBtcBalance().catch(() => 0.0),
                getNewAddress().catch(() => null)
            ]);

            const payload = [
                {
                    symbol: "ETH",
                    balance: parseFloat(ethBal),
                    chain: isEthOnline ? "Local Hardhat" : "Connecting",
                    address: ethWallet ? ethWallet.address : "0x00...00"
                },
                {
                    symbol: "BTC",
                    balance: parseFloat(btcBal),
                    chain: "Regtest",
                    address: btcAddr || "Check bitcoind"
                },
                {
                    symbol: "SOL",
                    balance: 0.0,
                    chain: "Solana",
                    address: SOL_ADDRESS
                },
                {
                    symbol: "USDT",
                    balance: 0.0,
                    chain: "Ethereum",
                    address: ethWallet ? ethWallet.address : "0x00...00"
                }
            ];

            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(payload));

        } catch (e) {
            console.error("API Error:", e);
            res.writeHead(500);
            res.end(JSON.stringify({ error: "Internal Error" }));
        }
        return;
    }

    // POST /btc/mine
    if (req.url === "/btc/mine" && req.method === "POST") {
        try {
            const addr = await getNewAddress();
            if (!addr) throw new Error("BTC RPC Unreachable");
            await btcRpc("generatetoaddress", [1, addr]);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "mined", address: addr }));
        } catch (e) {
            res.writeHead(500);
            res.end(JSON.stringify({ error: e.message }));
        }
        return;
    }

    // POST /wallet/send
    if (req.url === "/wallet/send" && req.method === "POST") {
        let body = "";
        req.on("data", c => body += c);
        req.on("end", () => {
            console.log("Tx Request:", body);
            // Logic could be expanded to actually route tx to ETH/BTC
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "ok", txHash: "0xMockTxSuccessful" }));
        });
        return;
    }

    res.writeHead(404).end("Not Found");
});

server.listen(PORT, () => {
    console.log(`\n🌉 Master Bridge Controller running on ${PORT}`);
    console.log("-------------------------------------------------");
    console.log(`🟢 BTC: Expecting 'bitcoind -regtest' on 18443`);
    console.log(`🔵 ETH: Managed locally (Auto-spawn on 8545)`);
    console.log("-------------------------------------------------");
});

// Cleanup on exit
process.on('SIGINT', () => {
    if (hardhatProcess) {
        console.log("\n🛑 Stopping child Hardhat process...");
        hardhatProcess.kill();
    }
    process.exit();
});
