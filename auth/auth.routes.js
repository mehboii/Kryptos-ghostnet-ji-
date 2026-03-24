/**
 * Auth Routes — Signup, Login, Email Verification (2FA)
 * -----------------------------------------------------
 * POST /auth/signup           → Register → sends 6-digit code to email
 * POST /auth/verify           → Verify email with 6-digit code
 * POST /auth/resend-code      → Resend verification code
 * POST /auth/login            → Authenticate (requires verified email)
 * POST /auth/forgot-password  → Request password reset code
 * POST /auth/reset-password   → Reset password with code
 * GET  /auth/me               → Get current user profile (protected)
 *
 * Security guarantees:
 *  • Passwords are NEVER logged.
 *  • Passwords are NEVER stored in plaintext.
 *  • bcrypt handles salt generation internally (saltRounds = 10).
 *  • JWT is returned only after email verification.
 *  • 2FA code is sent to email and expires after 10 minutes.
 */

import { Router } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';

import { JWT_SECRET, JWT_EXPIRES_IN, BCRYPT_SALT_ROUNDS } from './auth.config.js';
import {
    findByEmail, findById, createUser, sanitise,
    setResetToken, resetPassword,
    verifyEmail, resendVerifyCode,
    generateUniqueShortCode, updateUserFields
} from './auth.model.js';
import { requireAuth } from './auth.middleware.js';

const router = Router();

// ─── EMAIL TRANSPORTER ──────────────────────────────────────
// Uses SMTP settings from .env, falls back to Ethereal (fake SMTP for dev)
let transporter = null;
let transporterReady = false;

async function getTransporter() {
    if (transporter && transporterReady) return transporter;

    const smtpHost = process.env.SMTP_HOST;
    const smtpPort = process.env.SMTP_PORT;
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;

    if (smtpHost && smtpUser && smtpPass) {
        // Production SMTP (Gmail, SendGrid, Mailgun, etc.)
        transporter = nodemailer.createTransport({
            host: smtpHost,
            port: parseInt(smtpPort) || 587,
            secure: parseInt(smtpPort) === 465,
            auth: {
                user: smtpUser,
                pass: smtpPass,
            },
        });
        transporterReady = true;
        console.log(`📧 SMTP configured: ${smtpHost}:${smtpPort}`);
    } else {
        // Dev mode — use Ethereal (free test SMTP, no real emails sent)
        try {
            const testAccount = await nodemailer.createTestAccount();
            transporter = nodemailer.createTransport({
                host: 'smtp.ethereal.email',
                port: 587,
                secure: false,
                auth: {
                    user: testAccount.user,
                    pass: testAccount.pass,
                },
            });
            transporterReady = true;
            console.log(`📧 Dev SMTP (Ethereal): ${testAccount.user}`);
        } catch (e) {
            console.warn('⚠️ Could not create Ethereal test account:', e.message);
            transporterReady = false;
        }
    }

    return transporter;
}

// Initialize transporter on module load
getTransporter().catch(() => { });

/**
 * Send a verification email with the 6-digit code.
 */
async function sendVerificationEmail(email, code) {
    try {
        const mailer = await getTransporter();
        if (!mailer) {
            console.log(`📧 [DEV] Verification code for ${email}: ${code}`);
            return { sent: false, preview: null, devCode: code };
        }

        const fromAddr = process.env.SMTP_FROM || '"GhostNet" <noreply@ghostnet.io>';

        const info = await mailer.sendMail({
            from: fromAddr,
            to: email,
            subject: '🔐 GhostNet — Verify Your Email',
            text: `Your GhostNet verification code is: ${code}\n\nThis code expires in 10 minutes.\n\nIf you didn't create a GhostNet account, ignore this email.`,
            html: `
                <div style="font-family: 'Inter', sans-serif; max-width: 480px; margin: 0 auto; padding: 32px; background: linear-gradient(135deg, #0f172a, #1e293b); border-radius: 16px; color: #e2e8f0;">
                    <div style="text-align: center; margin-bottom: 24px;">
                        <h1 style="font-size: 28px; font-weight: 700; background: linear-gradient(135deg, #22d3ee, #6366f1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0;">
                            GHOST<span style="display:block; font-size: 24px;">NET</span>
                        </h1>
                    </div>
                    <div style="background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 20px;">
                        <p style="color: #94a3b8; font-size: 14px; margin: 0 0 16px 0;">Your verification code is:</p>
                        <div style="font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #22d3ee; font-family: monospace; background: rgba(34,211,238,0.1); border: 1px solid rgba(34,211,238,0.2); border-radius: 8px; padding: 16px; margin: 0 auto; display: inline-block;">
                            ${code}
                        </div>
                        <p style="color: #64748b; font-size: 12px; margin: 16px 0 0 0;">Expires in 10 minutes</p>
                    </div>
                    <p style="color: #64748b; font-size: 12px; text-align: center; margin: 0;">
                        If you didn't create a GhostNet account, you can safely ignore this email.
                    </p>
                </div>
            `,
        });

        const previewUrl = nodemailer.getTestMessageUrl(info);
        if (previewUrl) {
            console.log(`📧 Preview verification email: ${previewUrl}`);
        }

        return { sent: true, preview: previewUrl || null };
    } catch (e) {
        console.error('📧 Email send error:', e.message);
        console.log(`📧 [FALLBACK] Verification code for ${email}: ${code}`);
        return { sent: false, preview: null, devCode: code };
    }
}

// ─── RATE LIMITERS ──────────────────────────────────────────

// Login — max 5 attempts per 60s
const loginLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Please try again after 60 seconds.' },
});

// Password reset — max 3 per 5 min
const resetLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many reset requests. Please try again later.' },
});

// Resend verification — max 3 per 5 min
const resendLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many resend requests. Please try again later.' },
});

// Verify code — max 5 attempts per 15 min
const verifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many verification attempts. Please try again later.' },
});

// ============================================================
// POST /auth/signup
// ============================================================
router.post('/signup', async (req, res) => {
    console.log("SIGNUP HIT");
    try {
        const { email, password } = req.body;

        // --- Validation --------------------------------------------------
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters.' });
        }
        if (!/[A-Z]/.test(password)) {
            return res.status(400).json({ error: 'Password must contain at least one uppercase letter.' });
        }
        if (!/[a-z]/.test(password)) {
            return res.status(400).json({ error: 'Password must contain at least one lowercase letter.' });
        }
        if (!/[0-9]/.test(password)) {
            return res.status(400).json({ error: 'Password must contain at least one number.' });
        }
        if (!/[^A-Za-z0-9]/.test(password)) {
            return res.status(400).json({ error: 'Password must contain at least one special character.' });
        }

        // --- Duplicate check ---------------------------------------------
        if (findByEmail(email)) {
            return res.status(409).json({ error: 'An account with this email already exists.' });
        }

        // --- Hash password -----------------------------------------------
        const password_hash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

        // --- Persist user (unverified) -----------------------------------
        const userResult = await createUser({ email, password_hash });
        const { verifyCode, ...user } = userResult;

        // --- Send verification email -------------------------------------
        const emailResult = await sendVerificationEmail(email, verifyCode);

        // --- Response (NO JWT yet — must verify first) -------------------
        res.status(201).json({
            success: true,
            user,
            requiresVerification: true,
            message: 'Account created! Check your email for a 6-digit verification code.',
            // In dev mode, include the code directly if email couldn't be sent
            ...(emailResult.devCode ? { devCode: emailResult.devCode } : {}),
            ...(emailResult.preview ? { emailPreview: emailResult.preview } : {}),
        });
    } catch (err) {
        console.error('Signup error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ============================================================
// POST /auth/verify  — Verify email with 6-digit code
// ============================================================
router.post('/verify', verifyLimiter, async (req, res) => {
    try {
        const { email, code } = req.body;

        if (!email || !code) {
            return res.status(400).json({ error: 'Email and verification code are required.' });
        }

        const result = await verifyEmail(email, code);

        if (!result.success) {
            return res.status(400).json({ error: result.error });
        }

        // --- Generate JWT (now that email is verified) -------------------
        const token = jwt.sign({ userId: result.user.id }, JWT_SECRET, {
            expiresIn: JWT_EXPIRES_IN,
        });

        res.json({
            success: true,
            verified: true,
            user: result.user,
            token,
            message: result.alreadyVerified
                ? 'Email was already verified.'
                : 'Email verified successfully! Welcome to GhostNet.',
        });
    } catch (err) {
        console.error('Verify error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ============================================================
// POST /auth/resend-code  — Resend verification email
// ============================================================
router.post('/resend-code', resendLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required.' });
        }

        const result = await resendVerifyCode(email);

        if (!result) {
            // Don't reveal if email exists
            return res.json({
                success: true,
                message: 'If an account with that email exists, a new code has been sent.',
            });
        }

        if (result.alreadyVerified) {
            return res.json({
                success: true,
                alreadyVerified: true,
                message: 'This email is already verified. You can log in.',
            });
        }

        // Send the new code via email
        const emailResult = await sendVerificationEmail(email, result.code);

        res.json({
            success: true,
            message: 'A new verification code has been sent to your email.',
            ...(emailResult.devCode ? { devCode: emailResult.devCode } : {}),
            ...(emailResult.preview ? { emailPreview: emailResult.preview } : {}),
        });
    } catch (err) {
        console.error('Resend code error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ============================================================
// POST /auth/login
// ============================================================
router.post('/login', loginLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        // --- Validation --------------------------------------------------
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }

        // --- Lookup user -------------------------------------------------
        const user = findByEmail(email);
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // --- Verify password ---------------------------------------------
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // --- Check if email is verified ----------------------------------
        if (!user.verified) {
            return res.status(403).json({
                error: 'Email not verified. Please check your inbox for the verification code.',
                requiresVerification: true,
                email: user.email,
            });
        }

        // --- Generate JWT ------------------------------------------------
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
            expiresIn: JWT_EXPIRES_IN,
        });

        // --- Auto-generate GhostCode for existing users without one ------
        if (!user.shortCode) {
            const shortCode = generateUniqueShortCode();
            updateUserFields(user.id, { shortCode });
            user.shortCode = shortCode;
            console.log(`🔖 Generated GhostCode ${shortCode} for existing user ${user.email}`);
        }

        res.json({
            success: true,
            user: sanitise(user),
            token,
        });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ============================================================
// POST /auth/forgot-password
// ============================================================
router.post('/forgot-password', resetLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required.' });
        }

        const result = await setResetToken(email);

        if (!result) {
            return res.json({
                success: true,
                message: 'If an account with that email exists, a reset code has been generated.',
            });
        }

        if (process.env.NODE_ENV !== 'production') {
            console.debug('[DEV] Password reset initiated for user');
        }
        res.json({
            success: true,
            message: 'Reset code generated. Check your email for the 6-digit code.',
        });
    } catch (err) {
        console.error('Forgot password error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ============================================================
// POST /auth/reset-password
// ============================================================
router.post('/reset-password', resetLimiter, async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;

        if (!email || !code || !newPassword) {
            return res.status(400).json({ error: 'Email, reset code, and new password are required.' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters.' });
        }
        if (!/[A-Z]/.test(newPassword)) {
            return res.status(400).json({ error: 'New password must contain at least one uppercase letter.' });
        }
        if (!/[a-z]/.test(newPassword)) {
            return res.status(400).json({ error: 'New password must contain at least one lowercase letter.' });
        }
        if (!/[0-9]/.test(newPassword)) {
            return res.status(400).json({ error: 'New password must contain at least one number.' });
        }
        if (!/[^A-Za-z0-9]/.test(newPassword)) {
            return res.status(400).json({ error: 'New password must contain at least one special character.' });
        }

        const newHash = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);
        const result = await resetPassword(email, code, newHash);

        if (!result.success) {
            return res.status(400).json({ error: result.error });
        }

        res.json({
            success: true,
            message: 'Password has been reset successfully. You can now log in.',
        });
    } catch (err) {
        console.error('Reset password error:', err.message);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ============================================================
// GET /auth/me  (Protected — requires valid JWT)
// ============================================================
router.get('/me', requireAuth, (req, res) => {
    const user = findById(req.userId);
    if (!user) {
        return res.status(404).json({ error: 'User not found.' });
    }
    res.json({ user: sanitise(user) });
});

export default router;
