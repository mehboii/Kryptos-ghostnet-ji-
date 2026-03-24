const http = require('http');

const RPC_USER = process.env.BTC_RPC_USER;
const RPC_PASS = process.env.BTC_RPC_PASS;
if (!RPC_USER || !RPC_PASS) {
    console.error('[BTC-RPC] FATAL: BTC_RPC_USER and BTC_RPC_PASS must be set');
    process.exit(1);
}
const RPC_PORT = process.env.BTC_RPC_PORT || 18443;
const RPC_HOST = '127.0.0.1';

// Basic JSON-RPC wrapper for Bitcoin Core
async function btcRpc(method, params = []) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify({
            jsonrpc: '1.0',
            id: 'ghostnet-btc',
            method: method,
            params: params
        });

        const options = {
            hostname: RPC_HOST,
            port: RPC_PORT,
            path: '/',
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain',
                'Authorization': 'Basic ' + Buffer.from(`${RPC_USER}:${RPC_PASS}`).toString('base64'),
                'Content-Length': data.length
            }
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                if (res.statusCode === 401) return reject(new Error('BTC RPC Auth Failed'));
                if (res.statusCode !== 200) return reject(new Error(`BTC RPC Error: ${res.statusCode} ${body}`));

                try {
                    const json = JSON.parse(body);
                    if (json.error) return reject(new Error(json.error.message));
                    resolve(json.result);
                } catch (e) {
                    reject(e);
                }
            });
        });

        req.on('error', (e) => reject(new Error(`BTC RPC Connection Failed: ${e.message}`)));
        req.write(data);
        req.end();
    });
}

// Helper to get formatted balance
async function getBtcBalance() {
    try {
        // Get wallet balance. If no wallet loaded, this might fail or return 0
        const bal = await btcRpc('getbalance');
        return bal;
    } catch (e) {
        console.warn(`⚠️ BTC Regtest: ${e.message}`);
        return 0.0;
    }
}

async function getNewAddress() {
    try {
        return await btcRpc('getnewaddress');
    } catch (e) {
        return null;
    }
}

module.exports = { btcRpc, getBtcBalance, getNewAddress };
