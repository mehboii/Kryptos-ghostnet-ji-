
const bleno = require('@abandonware/bleno');

// Constants must match the browser code
const SERVICE_UUID = "67686f73-746e-6574-2d6d-657368000000"; // ghostnet-mesh
const CHAR_PEER_ID = "67686f73-746e-6574-2d69-640000000000"; // ghostnet-id
const CHAR_PUB_KEY = "67686f73-746e-6574-2d6b-657900000000"; // ghostnet-key
const CHAR_DATA = "67686f73-746e-6574-2d64-617461000000"; // ghostnet-data

const myName = "GhostNode";

console.log(`Starting GhostNet Peripheral: ${myName}`);

let updateCallback = null;

// Define Characteristics
const PeerIdChar = new bleno.Characteristic({
    uuid: CHAR_PEER_ID,
    properties: ['read'],
    value: Buffer.from(myName)
});

const PubKeyChar = new bleno.Characteristic({
    uuid: CHAR_PUB_KEY,
    properties: ['read'],
    value: Buffer.from("PC_PublicKey_Here")
});

const DataChar = new bleno.Characteristic({
    uuid: CHAR_DATA,
    properties: ['read', 'write', 'notify'],
    onWriteRequest: (data, offset, withoutResponse, callback) => {
        const msg = data.toString('utf-8');
        console.log(`[Recv] ${msg}`);

        // Echo back for testing
        if (updateCallback) {
            const reply = JSON.stringify({
                from: myName,
                body: `Echo: ${msg}`,
                ts: Date.now()
            });
            updateCallback(Buffer.from(reply));
        }

        callback(bleno.Characteristic.RESULT_SUCCESS);
    },
    onSubscribe: (maxValueSize, callback) => {
        console.log("Client Subscribed to updates");
        updateCallback = callback;
    },
    onUnsubscribe: () => {
        console.log("Client Unsubscribed");
        updateCallback = null;
    }
});

// Define Service
const GhostService = new bleno.PrimaryService({
    uuid: SERVICE_UUID,
    characteristics: [
        PeerIdChar,
        PubKeyChar,
        DataChar
    ]
});

// Wait for state change
bleno.on('stateChange', (state) => {
    console.log(`Bleno State: ${state}`);
    if (state === 'poweredOn') {
        bleno.startAdvertising(myName, [SERVICE_UUID]);
    } else {
        bleno.stopAdvertising();
    }
});

bleno.on('advertisingStart', (error) => {
    if (!error) {
        console.log('✅ Advertising started! Phone can now scan for "GhostNode"');
        bleno.setServices([GhostService]);
    } else {
        console.error('Advertising Error:', error);
    }
});

bleno.on('accept', (clientAddress) => {
    console.log(`Connection accepted from: ${clientAddress}`);
    // Advertising automatically stops on connection.
});

bleno.on('disconnect', (clientAddress) => {
    console.log(`Client ${clientAddress} disconnected. Restarting advertising...`);
    // Restart advertising so we can be found again
    bleno.startAdvertising(myName, [SERVICE_UUID]);
});
