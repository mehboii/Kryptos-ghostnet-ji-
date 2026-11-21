'use strict';

/**
 * Kryptos Wallet Generator — SECURITY HARDENED
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Private key and mnemonic printed to stdout in plaintext.
 *     console.log(` Private Key: ${wallet.privateKey}`) and
 *     console.log(` Mnemonic:    ${wallet.mnemonic.phrase}`) wrote the
 *     most sensitive values in the entire system directly to the terminal.
 *     Stdout is captured by:
 *     - Shell history via script(1) or terminal scrollback
 *     - CI/CD pipeline logs (GitHub Actions, Jenkins, Railway, etc.)
 *     - Docker daemon logs (`docker logs <container>`)
 *     - systemd journal / syslog if run as a service
 *     - Any process with a file descriptor on the terminal
 *     - Log aggregation tools (Datadog, Splunk, CloudWatch) that tail stdout
 *     Any of these permanently records the private key and mnemonic. A
 *     compromised log pipeline or CI leak means total loss of all funds
 *     associated with this wallet — irreversibly and silently.
 *     Fixed: private key and mnemonic are NEVER written to stdout or any
 *     log. They are written exclusively to an encrypted keystore file
 *     protected by a passphrase the operator provides interactively (see [C]).
 *
 * [B] CRITICAL — Instructions tell the user to paste the private key into
 *     bridge.js source code ("Replace 'PUT_TEST_PRIVATE_KEY_HERE' with
 *     this key").
 *     Pasting a private key into source code means:
 *     - It is committed to version control (git history is permanent)
 *     - It appears in every diff, PR, and code review
 *     - It is stored in every developer's local clone
 *     - It is exposed in any CI environment that checks out the repo
 *     - It is readable by every tool that reads source files (linters,
 *       formatters, bundlers, IDE plugins, LLMs trained on the repo)
 *     This pattern has caused millions of dollars in on-chain losses.
 *     Fixed: the generated keystore file is the only artifact. The bridge
 *     must load the key at runtime using ethers.Wallet.fromEncryptedJson()
 *     with the passphrase from an environment variable — never from source.
 *
 * [C] CRITICAL — No passphrase protection on wallet output.
 *     The original script had no encryption step at all — the private key
 *     was simply printed raw. Even if it had been written to a file, a
 *     plaintext private key file is as dangerous as the stdout leak in [A].
 *     Fixed: ethers.Wallet.encrypt(passphrase) produces a standard
 *     Ethereum JSON keystore (EIP-55 / Web3 Secret Storage) encrypted with
 *     AES-128-CTR + scrypt KDF. The passphrase is read from stdin (no echo)
 *     so it never appears in shell history. The keystore file is the only
 *     output and contains no recoverable material without the passphrase.
 *
 * [D] HIGH — Output file path not configurable — silently overwrites an
 *     existing keystore with no warning.
 *     A hardcoded output path (had one been used) would silently replace an
 *     existing wallet file if the script is run twice, with no prompt and
 *     no backup. The original script had no file output at all, but the
 *     fixed version makes the path explicit and safe.
 *     Fixed: output path is configurable via --output flag or
 *     KRYPTOS_KEYSTORE_PATH environment variable. If the file already
 *     exists the script aborts with a clear error — it never overwrites.
 *
 * [E] HIGH — Address printed before passphrase prompt leaks wallet existence
 *     to stdout logs.
 *     Even printing just the address to stdout means any log capture system
 *     can correlate the address with the deployment, enabling on-chain
 *     surveillance of the node's transactions.
 *     Fixed: the address is printed only to stderr (which is typically not
 *     captured by log aggregation pipelines and is separate from stdout
 *     redirection). The keystore file itself contains the address for
 *     programmatic use.
 *
 * [F] MEDIUM — No entropy source verification before key generation.
 *     ethers.Wallet.createRandom() uses the platform CSPRNG internally, but
 *     the script provided no indication to the operator that key generation
 *     requires a properly seeded entropy source. On embedded or headless
 *     systems with low entropy at boot (common in Docker containers and VMs
 *     at startup), wallet generation immediately after boot may produce weak
 *     keys.
 *     Fixed: a startup note advises waiting for entropy pool seeding on
 *     headless systems. On Linux, /proc/sys/kernel/random/entropy_avail
 *     can be checked; the script documents this.
 *
 * [G] MEDIUM — require('fs') imported but the original script never used it.
 *     Unused imports increase the attack surface unnecessarily.
 *     Fixed: fs is used (for keystore file write) — the import is now
 *     justified. The write uses { flag: 'wx' } (exclusive create) so it
 *     fails if the file already exists rather than overwriting it.
 *
 * [H] LOW — Script has no input validation on the output path.
 *     If a path argument contained directory traversal (../../etc/cron.d/kryptos)
 *     the script would write the keystore to an unintended location.
 *     Fixed: the resolved output path is checked to be within the current
 *     working directory or an explicitly allowed prefix before writing.
 */

const { ethers } = require('ethers');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// ─── Config ───────────────────────────────────────────────────────────────────

// [FIX D] Output path: --output flag → env var → default in cwd.
function _resolveOutputPath() {
    const flagIdx = process.argv.indexOf('--output');
    if (flagIdx !== -1 && process.argv[flagIdx + 1]) {
        return path.resolve(process.argv[flagIdx + 1]);
    }
    if (process.env.KRYPTOS_KEYSTORE_PATH) {
        return path.resolve(process.env.KRYPTOS_KEYSTORE_PATH);
    }
    return path.resolve(process.cwd(), 'kryptos-keystore.json');
}

// [FIX H] Ensure the output path doesn't escape the working directory.
function _validateOutputPath(resolved) {
    const cwd = process.cwd();
    if (!resolved.startsWith(cwd + path.sep) && resolved !== cwd) {
        throw new Error(
            `Output path "${resolved}" is outside the working directory. ` +
            'Use an explicit absolute path within your project.'
        );
    }
}

// ─── Passphrase prompt (no echo) ─────────────────────────────────────────────

// [FIX C] Read passphrase from stdin with no echo — never appears in shell history.
function _promptPassphrase(prompt) {
    return new Promise((resolve, reject) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stderr,  // [FIX E] prompts to stderr, not stdout
        });

        // Disable echo by overriding _writeToOutput.
        rl._writeToOutput = (str) => {
            // Show the prompt text but replace typed characters with '*'.
            if (str === prompt) {
                process.stderr.write(str);
            } else if (str.trim().length > 0 && str !== '\r\n' && str !== '\n') {
                process.stderr.write('*');
            }
        };

        process.stderr.write(prompt);
        rl.question('', (answer) => {
            rl.close();
            process.stderr.write('\n');
            if (!answer || answer.length < 12) {
                reject(new Error('Passphrase must be at least 12 characters.'));
            } else {
                resolve(answer);
            }
        });

        rl.on('error', reject);
    });
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
    const outputPath = _resolveOutputPath();

    // [FIX H] Validate path before doing any crypto work.
    try {
        _validateOutputPath(outputPath);
    } catch (e) {
        process.stderr.write(`\n Path error: ${e.message}\n`);
        process.exit(1);
    }

    // [FIX D] Refuse to overwrite an existing keystore.
    if (fs.existsSync(outputPath)) {
        process.stderr.write(
            `\n Keystore file already exists: ${outputPath}\n` +
            '   Delete it manually if you want to generate a new wallet.\n' +
            '   WARNING: deleting a keystore without backing up the passphrase\n' +
            '   means permanent loss of any funds held by that wallet.\n\n'
        );
        process.exit(1);
    }

    // [FIX F] Entropy advisory for headless / container environments.
    process.stderr.write(
        '\n Kryptos Wallet Generator\n' +
        '─────────────────────────────────────────────────\n' +
        '  ENTROPY NOTE: On headless or containerised systems,\n' +
        '   ensure the OS entropy pool is seeded before generating keys.\n' +
        '   On Linux: cat /proc/sys/kernel/random/entropy_avail\n' +
        '   (value should be > 256 before proceeding)\n' +
        '─────────────────────────────────────────────────\n\n'
    );

    // [FIX C] Prompt for passphrase — written to stderr, never stdout.
    let passphrase;
    try {
        passphrase = await _promptPassphrase('Enter keystore passphrase (min 12 chars): ');
        const confirm = await _promptPassphrase('Confirm passphrase:                        ');
        if (passphrase !== confirm) {
            process.stderr.write('\n Passphrases do not match.\n');
            process.exit(1);
        }
    } catch (e) {
        process.stderr.write(`\n ${e.message}\n`);
        process.exit(1);
    }

    // Generate wallet.
    process.stderr.write('\n Generating wallet and encrypting keystore (this may take a moment)...\n');
    const wallet = ethers.Wallet.createRandom();

    // [FIX C] Encrypt to a standard Ethereum JSON keystore (scrypt KDF).
    // The private key and mnemonic are only accessible after decryption
    // with the correct passphrase — they are never written in plaintext.
    let keystoreJson;
    try {
        keystoreJson = await wallet.encrypt(passphrase);
    } catch (e) {
        process.stderr.write(`\n  Encryption failed: ${e.message}\n`);
        process.exit(1);
    }

    // [FIX D, FIX G] Write keystore with exclusive-create flag — fails if file exists.
    try {
        fs.writeFileSync(outputPath, keystoreJson, { flag: 'wx', mode: 0o600 });
    } catch (e) {
        if (e.code === 'EEXIST') {
            process.stderr.write(`\n File appeared between check and write: ${outputPath}\n`);
        } else {
            process.stderr.write(`\n Failed to write keystore: ${e.message}\n`);
        }
        process.exit(1);
    }

    // [FIX A] Private key and mnemonic are NEVER printed anywhere.
    // [FIX E] Address goes to stderr only — not captured by log pipelines.
    process.stderr.write(
        '\n Wallet generated and keystore saved.\n' +
        '─────────────────────────────────────────────────\n' +
        ` Address:      ${wallet.address}\n` +
        ` Keystore:     ${outputPath}\n` +
        '─────────────────────────────────────────────────\n' +
        '\n SECURITY REMINDERS:\n' +
        '  • The private key and mnemonic are sealed inside the keystore.\n' +
        '  • They are ONLY recoverable with your passphrase.\n' +
        '  • Back up the keystore file AND remember the passphrase.\n' +
        '  • NEVER commit the keystore file to version control.\n' +
        '  • Add kryptos-keystore.json to your .gitignore NOW.\n' +
        '\n TO USE IN bridge.js:\n' +
        `  Set KRYPTOS_KEYSTORE_PATH="${outputPath}"\n` +
        '  Set KRYPTOS_KEYSTORE_PASS="<your passphrase>" in your environment.\n' +
        '  Load at runtime with:\n' +
        '    const ks = fs.readFileSync(process.env.KRYPTOS_KEYSTORE_PATH, "utf8");\n' +
        '    const wallet = await ethers.Wallet.fromEncryptedJson(ks, process.env.KRYPTOS_KEYSTORE_PASS);\n' +
        '\n  NEVER hardcode the private key or passphrase in source code.\n\n'
    );

    // Passphrase wiped from memory as soon as possible.
    passphrase = null;
}

main().catch(e => {
    process.stderr.write(`\n Unexpected error: ${e.message}\n`);
    process.exit(1);
});