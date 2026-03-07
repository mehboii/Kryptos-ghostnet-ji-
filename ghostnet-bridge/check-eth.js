const { ethers } = require("ethers");

const RPC_URL = "http://127.0.0.1:8545";

async function checkEth() {
    console.log(`🔍 Checking Ethereum Node at ${RPC_URL}...`);
    try {
        const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, { staticNetwork: true });

        // Timeout promise race
        const timeout = new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Connection Timed Out (3s)")), 3000)
        );

        const net = await Promise.race([
            provider.getNetwork(),
            timeout
        ]);

        console.log(`✅ ETH ONLINE!`);
        console.log(`   Chain ID: ${net.chainId}`);
        console.log(`   Block Number: ${await provider.getBlockNumber()}`);
        process.exit(0);
    } catch (e) {
        console.error(`❌ ETH OFFLINE: ${e.message}`);
        console.error(`   -> Is Hardhat/Ganache running?`);
        console.error(`   -> Did you run 'npx hardhat node'?`);
        process.exit(1);
    }
}

checkEth();
