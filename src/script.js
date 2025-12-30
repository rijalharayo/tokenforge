const jwt = require("jsonwebtoken");

// Helper: Safe token check
const isValidTokenString = (token) => token && typeof token === 'string' && token.trim().length > 0;

// Verify and return decoded payload (or null on error)
const verifyToken = (token) => {
     if (!isValidTokenString(token)) return null;
     try {
          return jwt.verify(token, process.env.JWT_SECRET);
     } 
     catch (error) {
          console.error("Token verification failed:", error.message);
          return null;
     }
};

// Check if token exists and is non-empty
const tokenExists = (token) => !!isValidTokenString(token);

/**
 * Create a signed JWT token.
 * @param {object} payload - Data to encode in token
 * @param {object} [options={ expiresIn: '24h' }] - jwt.sign options
 * @returns {string|null} Signed token or null on failure
 */
const createToken = (payload, options = { expiresIn: '24h' }) => {
    if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET environment variable is required');
    }
    try {
        return jwt.sign(payload, process.env.JWT_SECRET, options);
    } catch (error) {
        console.error("Token creation failed:", error);
        return null;
    }
};

/**
 * Fetch new auth cookies from backend and return set-cookie headers
 * @param {Function} fetchMethod - Async function that makes the request (e.g., axios.post)
 * @returns {Array<string>|null} set-cookie array or null
 */
const createTokenFromBackend = async (req, fetchMethod) => {
     if (!req || !req.headers || !req.headers.cookie) {
          console.error("Missing request headers for session token creation");
          return null;
     }
     try {
          const response = await fetchMethod();

          return response.headers["set-cookie"] || null;
     } 
     catch (error) {
          console.error("Session token refresh failed:", error);
          return null;
     }
};

/**
 * Parse set-cookie headers and set them securely on Express response
 * Applies secure defaults while respecting backend-provided attributes
 * @param {Array<string>} setCookieHeaders
 * @param {object} res - Express response object
 */
const tokenParser = (setCookieHeaders, res) => {
    if (!Array.isArray(setCookieHeaders) || setCookieHeaders.length === 0) return;

    tokens.forEach(cookieStr => {
        if (!cookieStr || typeof cookieStr !== 'string') return;

        const parts = cookieStr.split(";").map(part => part.trim());
        if (parts.length === 0) return;

        const [nameValue] = parts;
        const [name, value] = nameValue.split("=", 2); // Limit split to avoid issues
        if (!name || !value) return;

        // Secure defaults for auth cookies
        const options = {
            httpOnly: true,  // Prevent JS access
            secure: false,
            sameSite: "strict",
            path: "/",
            maxAge: undefined,
            domain: undefined  // Add if needed: process.env.COOKIE_DOMAIN
        };

        // Parse attributes
        parts.slice(1).forEach(attr => {
            const [key, val] = attr.split("=", 2);
            const attrName = key.toLowerCase().replace(/-/g, ''); // Handle kebab-case

            switch (attrName) {
                case 'httponly':
                    options.httpOnly = true;
                    break;
                case 'samesite':
                    options.sameSite = val || "strict";
                    break;
                case 'secure':
                    options.secure = true;
                    break;
                case 'path':
                    options.path = val;
                    break;
                case 'max-age':
                case 'maxage':
                    const ageMs = parseInt(val, 10) * 1000;
                    options.maxAge = Number.isNaN(ageMs) ? undefined : ageMs;
                    break;
                case 'domain':
                    options.domain = val;
                    break;
                // Ignore non-standard like 'priority'
            }
        });

        res.cookie(name.trim(), value.trim(), options);
    });
};

module.exports = {
    verifyToken,
    tokenExists,
    createToken,
    createTokenFromBackend,
    tokenParser
};