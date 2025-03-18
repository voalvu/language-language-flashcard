const http = require('http');
const fs = require('fs');
const url = require('url');
const querystring = require('querystring');
const { get } = require('@vercel/edge-config'); // Import Edge Config

// Helper function to generate a JWT
const generateToken = (userId, secretKey) => {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { userId, exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 30) }; // 30 days expiry
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    const signature = require('crypto')
        .createHmac('sha256', secretKey)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest('base64');
    return `${encodedHeader}.${encodedPayload}.${signature}`;
};

// Helper function to verify a JWT
const verifyToken = (token, secretKey) => {
    try {
        const [encodedHeader, encodedPayload, signature] = token.split('.');
        const expectedSignature = require('crypto')
            .createHmac('sha256', secretKey)
            .update(`${encodedHeader}.${encodedPayload}`)
            .digest('base64');
        if (signature !== expectedSignature) {
            return null; // Invalid signature
        }
        const payload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
        if (payload.exp < Math.floor(Date.now() / 1000)) {
            return null; // Token expired
        }
        return payload; // Valid token
    } catch (err) {
        return null; // Invalid token
    }
};

const server = http.createServer(async (req, res) => {
    const { pathname, query } = url.parse(req.url);
    const params = querystring.parse(query);

    // Fetch the SECRET_KEY from Edge Config
    let SECRET_KEY;
    try {
        SECRET_KEY = await get('secret_key'); // Fetch the "secret_key" from Edge Config
        if (!SECRET_KEY) {
            throw new Error('SECRET_KEY not found in Edge Config');
        }
    } catch (err) {
        console.error('Error fetching SECRET_KEY from Edge Config:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
        return;
    }

    // Serve the login page
    if (pathname === '/' && req.method === 'GET') {
        fs.readFile('./index.html', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    }

    // Handle login request
    else if (pathname === '/login' && req.method === 'POST') {
        let body = '';
        req.on('data', (chunk) => {
            body += chunk.toString();
        });
        req.on('end', async () => {
            const { username, password } = querystring.parse(body);

            // Fetch the login object from Vercel Edge Config
            try {
                const loginConfig = await get('login'); // Fetch the "login" key from Edge Config
                if (!loginConfig || !loginConfig.username || !loginConfig.password) {
                    throw new Error('Login configuration not found in Edge Config');
                }

                // Compare credentials
                if (username === loginConfig.username && password === loginConfig.password) {
                    const token = generateToken(1, SECRET_KEY); // Use a fixed user ID (e.g., 1)
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ token }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid credentials' }));
                }
            } catch (err) {
                console.error('Error fetching Edge Config:', err);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Internal Server Error' }));
            }
        });
    }

    // Protected route (requires token)
    else if (pathname === '/protected' && req.method === 'GET') {
        const token = req.headers.authorization?.split(' ')[1]; // Extract token from header
        if (!token) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'No token provided' }));
            return;
        }
        const payload = verifyToken(token, SECRET_KEY);
        if (!payload) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid or expired token' }));
            return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: `Welcome, user ${payload.userId}` }));
    }

    // Handle 404
    else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

const PORT = 3006;
server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});