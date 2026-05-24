// [FIX 24] HTML escaping to prevent XSS via innerHTML
function escapeHtml(str) {
    if (typeof str !== 'string') str = String(str ?? '');
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' };
    return str.replace(/[&<>"']/g, c => map[c]);
}

document.addEventListener('DOMContentLoaded', () => {
    // === State & References ===
    const els = {
        authLayer: document.getElementById('auth-layer'),
        appLayer: document.getElementById('app-layer'),
        connectBtn: document.getElementById('connect-btn'),
        entropyBar: document.getElementById('entropy-bar'),
        authConsole: document.getElementById('auth-console'),
        identityStatus: document.getElementById('identity-status'),

        canvas: document.getElementById('network-canvas'),
        logs: document.getElementById('network-logs'),
        chatInput: document.getElementById('msg-input'),
        sendBtn: document.getElementById('send-btn'),
        messages: document.getElementById('chat-messages'),

        // Toggle Chat
        // ... (chat handles itself)

        // BLE
        meshList: document.querySelector('.mesh-device-list'),
        meshControls: document.querySelector('.mesh-controls'),

        // Vault
        vaultDropzone: document.getElementById('vault-dropzone'),
        uploadProgress: document.getElementById('upload-progress'),
        uploadBar: document.getElementById('upload-bar'),
        uploadFilename: document.getElementById('uploading-filename'),
        fileList: document.querySelector('.file-list-content'), // Updated selector

        // Real IO
        realFileInput: document.getElementById('real-file-input'),
        btnSelectFile: document.getElementById('btn-select-file'),
        btnRecordVoice: document.getElementById('btn-record-voice'),
        audioPreviewContainer: document.getElementById('audio-preview-container'),
        audioPlayback: document.getElementById('audio-playback'),
        btnUploadVoice: document.getElementById('btn-upload-voice'),

        // New selectors
        navLinks: document.querySelectorAll('.nav-item'),
        tabContents: document.querySelectorAll('.view-panel')
    };

    // === 1. Auth / Login Simulation ===

    // Auto-start entropy generation
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 5;
        if (progress > 100) progress = 100;

        els.entropyBar.style.width = `${progress}%`;

        // Log simulation
        if (Math.random() > 0.7) {
            logAuth(`Capturing noise: ${Math.floor(Math.random() * 9999)}ms`);
        }

        if (progress === 100) {
            clearInterval(interval);
            els.connectBtn.disabled = false;
            els.identityStatus.innerText = "Ready (ECDSA-256)";
            els.identityStatus.style.color = "var(--neon-green)";
            logAuth("Identity generation complete.");
        }
    }, 100);

    function logAuth(text) {
        const div = document.createElement('div');
        div.innerText = `> ${text}`;
        els.authConsole.appendChild(div);
        els.authConsole.scrollTop = els.authConsole.scrollHeight;
    }

    // === 2. Navigation Logic ===

    // Auth Flow Fix
    els.connectBtn.addEventListener('click', () => {
        logAuth("Initiating Zero-Knowledge Proof Handshake...");
        els.connectBtn.innerText = "AUTHENTICATING...";

        setTimeout(() => {
            // Updated Auth Transition for Overlay
            els.authLayer.classList.remove('active');
            // Trigger Resize for charts once visible
            setTimeout(() => {
                resizeCanvas();
                requestAnimationFrame(animateNetwork);
            }, 100);
        }, 1500);
    });

    // Tab Switching
    els.navLinks.forEach(link => {
        link.addEventListener('click', () => {
            // Remove active from all nav items
            els.navLinks.forEach(l => l.classList.remove('active'));
            // Remove active from all panels
            els.tabContents.forEach(p => p.classList.remove('active'));

            // Activate clicked
            link.classList.add('active');
            const tabId = link.getAttribute('data-tab');
            const panel = document.getElementById(`${tabId}-tab`);
            if (panel) {
                panel.classList.add('active');

                // Special init for specific tabs
                if (tabId === 'network') resizeCanvas();

                // Update specific breadcrumb
                const pageTitle = document.getElementById('page-title');
                if (pageTitle) pageTitle.innerText = tabId.toUpperCase();
            }
        });
    });

    // === 3. Network Mesh Visualization (Canvas) ===

    let nodes = [];
    let ctx;
    let width, height;

    function initNetworkVis() {
        if (!els.canvas) return;
        ctx = els.canvas.getContext('2d');
        resizeCanvas();
        window.addEventListener('resize', resizeCanvas);

        // Create random nodes
        for (let i = 0; i < 30; i++) {
            nodes.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 1.5,
                vy: (Math.random() - 0.5) * 1.5,
                isRelay: Math.random() > 0.8
            });
        }

        requestAnimationFrame(animateNetwork);
    }

    function resizeCanvas() {
        if (!els.canvas.parentElement) return;
        width = els.canvas.parentElement.offsetWidth;
        height = els.canvas.parentElement.offsetHeight;
        els.canvas.width = width;
        els.canvas.height = height;
    }

    function animateNetwork() {
        ctx.clearRect(0, 0, width, height);

        // Update nodes
        nodes.forEach(node => {
            node.x += node.vx;
            node.y += node.vy;

            // Bounce
            if (node.x < 0 || node.x > width) node.vx *= -1;
            if (node.y < 0 || node.y > height) node.vy *= -1;

            // Draw Node
            ctx.fillStyle = node.isRelay ? '#00f3ff' : '#555';
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.isRelay ? 3 : 2, 0, Math.PI * 2);
            ctx.fill();
        });

        // Draw Connections
        ctx.strokeStyle = 'rgba(0, 243, 255, 0.15)';
        ctx.lineWidth = 1;

        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const dist = Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y);
                if (dist < 100) {
                    ctx.beginPath();
                    ctx.moveTo(nodes[i].x, nodes[i].y);
                    ctx.lineTo(nodes[j].x, nodes[j].y);
                    ctx.stroke();

                    // Traffic Packet Simulation (Onion Routing)
                    if (Math.random() > 0.98) {
                        launchOnionPacket(nodes[i], nodes[j]);
                    }
                }
            }
        }

        ctx.restore(); // Ensure we don't bleed styles

        // Update and draw active packets
        updateOnionPackets();

        requestAnimationFrame(animateNetwork);
    }

    // Onion Packet System
    let onionPackets = [];

    function launchOnionPacket(start, end) {
        onionPackets.push({
            x: start.x,
            y: start.y,
            tx: end.x,
            ty: end.y,
            layers: 3, // 3 Layers of encryption
            progress: 0
        });

        // Log Occasional Routing Event
        if (Math.random() > 0.8) {
            addLog(`ZK-Proof Verified: [ONION_HOP]`);
        }
    }

    function updateOnionPackets() {
        if (!ctx) return;
        for (let i = onionPackets.length - 1; i >= 0; i--) {
            let p = onionPackets[i];
            p.progress += 0.05; // Speed

            // Interpolate position
            let currX = p.x + (p.tx - p.x) * p.progress;
            let currY = p.y + (p.ty - p.y) * p.progress;

            // Draw Packet (Onion Layers)
            // Layer 1 (Outer) - Purple
            ctx.beginPath();
            ctx.fillStyle = `rgba(188, 19, 254, ${1 - p.progress})`; // Fades out as it "peels"
            ctx.arc(currX, currY, 6, 0, Math.PI * 2);
            ctx.fill();

            // Layer 2 (Inner) - Cyan
            ctx.beginPath();
            ctx.fillStyle = '#00f0ff';
            ctx.arc(currX, currY, 3, 0, Math.PI * 2);
            ctx.fill();

            // Finish
            if (p.progress >= 1) {
                onionPackets.splice(i, 1);
            }
        }
    }

    function addLog(msg) {
        if (!els.logs) return;
        const li = document.createElement('li');
        li.innerText = `[${new Date().toLocaleTimeString('en-GB')}] ${msg}`;
        els.logs.prepend(li); // Newest top
        if (els.logs.children.length > 20) els.logs.lastChild.remove();
    }

    // === 4. Chat System ===

    function addMessage(text, type) {
        const div = document.createElement('div');
        div.className = `msg ${type}`;
        div.innerText = text;
        els.messages.appendChild(div);
        els.messages.scrollTop = els.messages.scrollHeight;
    }

    if (els.sendBtn) {
        els.sendBtn.addEventListener('click', () => {
            const txt = els.chatInput.value.trim();
            if (!txt) return;

            addMessage(txt, 'sent');
            els.chatInput.value = '';

            // Simulate reply
            setTimeout(() => {
                const replies = [
                    "Ack. Packet received.",
                    "Decrypting... verification successful.",
                    "Node 0x4F requests confirmation.",
                    "Route unstable. Retrying handshake..."
                ];
                addMessage(replies[Math.floor(Math.random() * replies.length)], 'received');
            }, 1000 + Math.random() * 2000);
        });
    }

    if (els.chatInput) {
        els.chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') els.sendBtn.click();
        });
    }

    // === 5. Bluetooth Mesh Logic (Real Hardware Access + Visualization) ===

    // We try to access real hardware. If fails (no browser support), we fallback to simulation.
    async function startBleScan() {
        if (!els.meshList) return;

        const radarGrid = document.querySelector('.radar-grid');
        els.meshList.innerHTML = '<div class="empty-state">Requesting Hardware Access...<br><span style="font-size:0.8em">Please select a visible device to bridge.</span></div>';

        try {
            // "Real" Access Request
            const device = await navigator.bluetooth.requestDevice({
                acceptAllDevices: true,
                optionalServices: ['battery_service'] // Common service just to try an anchor
            });

            // If user selects a device
            addRealDeviceToList(device);
            // Add real node to mesh logic
            const meshNodes = [{ x: 200, y: 200 }];
            visualizeMeshNode(radarGrid, true, meshNodes);

        } catch (err) {
            console.log("Hardware scan cancelled or failed: " + err);
            // Fallback to simulation mode
            els.meshList.innerHTML = '<div class="empty-state">Running Passive Spectrum Scan...</div>';
            startSimulationScan();
        }
    }

    function addRealDeviceToList(device) {
        const div = document.createElement('div');
        div.className = 'mesh-device';
        div.style.padding = '1rem';
        div.style.borderBottom = '1px solid rgba(255,255,255,0.1)';
        div.style.display = 'flex';
        div.style.justifyContent = 'space-between';

        // [FIX 24] Escape device name/id to prevent XSS
        div.innerHTML = `
            <div class="device-info">
                <span style="display:block; font-weight:bold; color:var(--neon-green)">${escapeHtml(device.name || "Unknown Device")}</span>
                <span style="font-size:0.7em; color:#888">REAL HARDWARE ID: ${escapeHtml(device.id)}</span>
            </div>
            <div class="signal" style="color:var(--neon-green)">LINKED</div>
        `;
        els.meshList.innerHTML = ''; // Clear scan text
        els.meshList.prepend(div);
    }

    function startSimulationScan() {
        const deviceNames = ["Ghost_Relay_7A", "Pixel_6_Secure", "iPhone_Mesh_Node", "RPI_Zero_Bridge", "Unknown_Signal"];
        let found = 0;
        const radarGrid = document.querySelector('.radar-grid');

        // Clear old dots and reset mesh memory
        if (radarGrid) radarGrid.innerHTML = '';
        const meshNodes = [{ x: 200, y: 200 }]; // Start with self (center)

        const scanInterval = setInterval(() => {
            if (Math.random() > 0.6) {
                if (found === 0 && els.meshList.querySelector('.empty-state')) els.meshList.innerHTML = '';

                const name = deviceNames[Math.floor(Math.random() * deviceNames.length)];
                const rssi = -(Math.floor(Math.random() * 40) + 40);
                // [FIX 24] Use crypto.getRandomValues instead of Math.random for IDs
                const idBytes = new Uint8Array(2);
                crypto.getRandomValues(idBytes);
                const id = "0x" + Array.from(idBytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

                // Add to List
                const div = document.createElement('div');
                div.style.padding = '1rem';
                div.style.borderBottom = '1px solid rgba(255,255,255,0.1)';
                div.style.display = 'flex';
                div.style.justifyContent = 'space-between';
                // [FIX 24] Escape simulated device data
                div.innerHTML = `
                    <div class="device-info">
                        <span style="display:block; font-weight:bold; color:var(--neon-blue)">${escapeHtml(name)}</span>
                        <span style="font-size:0.7em; color:#666">ID: ${escapeHtml(id)}</span>
                        <span style="font-size:0.6em; color:var(--neon-green)">RELAY ACTIVE</span>
                    </div>
                    <div class="signal">
                        RSSI: ${rssi}dBm
                    </div>
                `;
                els.meshList.prepend(div);

                // Simulate "Mesh Hop" on Radar
                // Pass the shared 'meshNodes' array to find nearest neighbor
                visualizeMeshNode(radarGrid, false, meshNodes);

                found++;
                if (found > 8) clearInterval(scanInterval); // Find a few more nodes
            }
        }, 600);
    }

    function visualizeMeshNode(container, isReal, knownNodes) {
        if (!container) return;
        if (!knownNodes) knownNodes = [{ x: 200, y: 200 }]; // Fallback

        // Create Dot
        const dot = document.createElement('div');
        // Random placement but try to push outwards to simulate range extension
        const size = Math.random() * 250 + 50;
        const angle = Math.random() * Math.PI * 2;

        const x = Math.cos(angle) * (size / 2) + 200;
        const y = Math.sin(angle) * (size / 2) + 200;

        // Find nearest neighbor to connect to (Daisy Chain Relay Logic)
        let nearest = knownNodes[0];
        let minDist = 9999;

        knownNodes.forEach(node => {
            const d = Math.hypot(node.x - x, node.y - y);
            if (d < minDist) {
                minDist = d;
                nearest = node;
            }
        });

        // Store this new node for future hops
        knownNodes.push({ x, y });

        dot.style.position = 'absolute';
        dot.style.left = `${x}px`;
        dot.style.top = `${y}px`;
        dot.style.width = '6px';
        dot.style.height = '6px';
        dot.style.background = isReal ? 'var(--neon-green)' : 'var(--neon-cyan)';
        dot.style.borderRadius = '50%';
        dot.style.boxShadow = `0 0 10px ${isReal ? 'var(--neon-green)' : 'var(--neon-cyan)'}`;
        dot.style.animation = 'fadeIn 0.5s ease';

        container.appendChild(dot);

        // Draw Hop Line to NEAREST Neighbor (Simulates Relay)
        const line = document.createElement('div');
        const length = Math.hypot(x - nearest.x, y - nearest.y);
        line.style.position = 'absolute';
        line.style.top = `${nearest.y}px`;
        line.style.left = `${nearest.x}px`;
        line.style.width = `${length}px`;
        line.style.height = '1px';
        line.style.background = 'rgba(0, 240, 255, 0.4)'; // Brighter line
        line.style.transformOrigin = '0 0';
        line.style.transform = `rotate(${Math.atan2(y - nearest.y, x - nearest.x)}rad)`;

        container.appendChild(line);
    }

    // Bind the "Broadcast Beacon" button to the real scan
    if (els.meshControls) {
        const meshBtns = els.meshControls.querySelectorAll('button');
        if (meshBtns[0]) {
            meshBtns[0].addEventListener('click', startBleScan);
        }
    }

    // === 6. Real File Upload & Voice Recording ===

    // 6a. Select File Logic
    if (els.btnSelectFile) {
        els.btnSelectFile.addEventListener('click', () => {
            els.realFileInput.click();
        });
    }

    if (els.realFileInput) {
        els.realFileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                simulateUpload(file.name, file.size);
            }
        });
    }

    // 6b. Voice Recording Logic
    let mediaRecorder;
    let audioChunks = [];
    let isRecording = false;

    if (els.btnRecordVoice) {
        els.btnRecordVoice.addEventListener('mousedown', startRecording);
        els.btnRecordVoice.addEventListener('mouseup', stopRecording);
        els.btnRecordVoice.addEventListener('mouseleave', () => {
            if (isRecording) stopRecording();
        });

        // Touch support for mobile
        els.btnRecordVoice.addEventListener('touchstart', (e) => { e.preventDefault(); startRecording(); });
        els.btnRecordVoice.addEventListener('touchend', (e) => { e.preventDefault(); stopRecording(); });
    }

    async function startRecording() {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            alert("Microphone access not supported in this environment.");
            return;
        }

        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaRecorder = new MediaRecorder(stream);
            audioChunks = [];

            mediaRecorder.ondataavailable = event => {
                audioChunks.push(event.data);
            };

            mediaRecorder.onstop = () => {
                const audioBlob = new Blob(audioChunks, { type: 'audio/wav' });
                const audioUrl = URL.createObjectURL(audioBlob);
                els.audioPlayback.src = audioUrl;
                els.audioPreviewContainer.style.display = 'block';
                els.vaultDropzone.querySelector('.upload-actions').style.display = 'none';
            };

            mediaRecorder.start();
            isRecording = true;
            els.btnRecordVoice.innerText = "RECORDING... (RELEASE TO STOP)";
            els.btnRecordVoice.style.borderColor = "var(--alert-red)";
            els.btnRecordVoice.style.color = "var(--alert-red)";

        } catch (err) {
            console.error("Mic Error:", err);
            alert("Could not access microphone.");
        }
    }

    function stopRecording() {
        if (mediaRecorder && isRecording) {
            mediaRecorder.stop();
            isRecording = false;
            els.btnRecordVoice.innerText = "HOLD TO RECORD";
            els.btnRecordVoice.style.borderColor = "";
            els.btnRecordVoice.style.color = "";
        }
    }

    if (els.btnUploadVoice) {
        els.btnUploadVoice.addEventListener('click', () => {
            // Upload the recorded voice blob
            simulateUpload(`voice_record_${Date.now()}.wav`, 1024 * 500); // Mock size
            els.audioPreviewContainer.style.display = 'none';
            els.vaultDropzone.querySelector('.upload-actions').style.display = 'flex';
        });
    }

    function simulateUpload(filename, sizeBytes) {
        els.uploadProgress.style.display = 'block';
        els.vaultDropzone.style.display = 'none';

        // Format size
        const sizeStr = sizeBytes > 1000000 ? (sizeBytes / 1000000).toFixed(2) + " MB" : (sizeBytes / 1000).toFixed(2) + " KB";

        let progress = 0;
        els.uploadFilename.innerText = `${filename} (${sizeStr})`;

        const interval = setInterval(() => {
            progress += Math.random() * 5;
            if (progress >= 100) progress = 100;

            els.uploadBar.style.width = `${progress}%`;

            if (progress === 100) {
                clearInterval(interval);

                setTimeout(() => {
                    // Reset UI
                    els.uploadProgress.style.display = 'none';
                    els.vaultDropzone.style.display = 'block';

                    // Add file to list
                    const fileRow = document.createElement('div');
                    fileRow.className = 'file-item';
                    fileRow.style.borderLeft = '3px solid var(--neon-green)'; // Highlight new
                    fileRow.style.animation = 'fadeIn 0.5s ease';

                    const type = filename.split('.').pop().toUpperCase();
                    const shards = 12 + Math.floor(Math.random() * 10);

                    // [FIX 24] Escape filename in file list
                    fileRow.innerHTML = `
                        <span>${escapeHtml(filename)}</span>
                        <span>${escapeHtml(type)}</span>
                        <span>${shards}/${shards}</span>
                        <span class="status-ok">Synced (Local)</span>
                    `;

                    // Insert after header
                    els.fileList.insertBefore(fileRow, els.fileList.children[1]);

                }, 800);
            }
        }, 100);
    }

    // Start with Auth layer visible by default (css does this but ensure class is there)
    els.authLayer.classList.add('active');
});
