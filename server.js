/**
 * Server Entry Point
 * 
 * Configures and starts the Express server with comprehensive security middleware:
 *   - Helmet: Sets secure HTTP headers
 *   - CSRF Protection: Prevents cross-site request forgery
 *   - Cookie Parser: Parses cookies for JWT authentication
 *   - Input Parsing: JSON and URL-encoded body parsing with size limits
 *   - Error Handling: Centralized error handling middleware
 */

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const path = require('path');
require('dotenv').config();

const { initializeDatabase } = require('./models/db');
const authRoutes = require('./routes/auth');
const pageRoutes = require('./routes/pages');

// ─── Express App Setup ───────────────────────────────────────────────────────
const app = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ─────────────────────────────────────────────────────

// Helmet: Sets various HTTP security headers
// Includes X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, etc.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"]
        }
    }
}));

// Parse cookies (needed for JWT token extraction and CSRF)
app.use(cookieParser());

// Parse JSON request bodies with size limit (prevents payload attacks)
app.use(express.json({ limit: '10kb' }));

// Parse URL-encoded request bodies with size limit
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Serve static files from /public directory
app.use(express.static(path.join(__dirname, 'public')));

// ─── CSRF Protection ────────────────────────────────────────────────────────
// Uses cookie-based CSRF tokens. The token must be included in all
// state-changing requests (POST, PUT, DELETE) via the _csrf header.
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
});

// Apply CSRF protection to all routes
app.use(csrfProtection);

// ─── Routes ──────────────────────────────────────────────────────────────────

// Authentication API routes
app.use('/api/auth', authRoutes);

// Page serving routes
app.use('/', pageRoutes);

// ─── Error Handling Middleware ────────────────────────────────────────────────

/**
 * Centralized error handler.
 * Handles CSRF token errors, validation errors, and generic server errors.
 * Never exposes stack traces or sensitive information in production.
 */
app.use((err, req, res, next) => {
    // Handle CSRF token errors
    if (err.code === 'EBADCSRFTOKEN') {
        console.error('CSRF token validation failed');
        return res.status(403).json({
            success: false,
            errors: [{
                field: 'general',
                message: 'Invalid or missing CSRF token. Please refresh the page and try again.'
            }]
        });
    }

    // Log the error (but don't expose details to client)
    console.error('Server error:', err.message);

    // Send generic error response
    res.status(err.status || 500).json({
        success: false,
        errors: [{
            field: 'general',
            message: process.env.NODE_ENV === 'production'
                ? 'An unexpected error occurred. Please try again.'
                : err.message
        }]
    });
});

// ─── Start Server ────────────────────────────────────────────────────────────

/**
 * Initialize the database and start the Express server.
 * The server will only start after the database is successfully initialized.
 */
async function startServer() {
    try {
        // Initialize database (creates tables if they don't exist)
        await initializeDatabase();

        // Start listening for requests
        app.listen(PORT, () => {
            console.log(`
╔══════════════════════════════════════════════════╗
║                                                  ║
║   🔐 Secure Auth App is running!                 ║
║                                                  ║
║   Local:  http://localhost:${PORT}                 ║
║   Mode:   ${process.env.NODE_ENV || 'development'}                      ║
║                                                  ║
║   Pages:                                         ║
║   • Sign Up:    http://localhost:${PORT}/signup     ║
║   • Login:      http://localhost:${PORT}/login      ║
║   • Dashboard:  http://localhost:${PORT}/dashboard  ║
║                                                  ║
╚══════════════════════════════════════════════════╝
      `);
        });
    } catch (error) {
        console.error('Failed to start server:', error.message);
        process.exit(1);
    }
}

startServer();
