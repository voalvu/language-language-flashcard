const http = require('http');
const fs = require('fs');
const url = require('url');
const querystring = require('querystring');
const { get } = require('@vercel/edge-config');

const generateToken = (userId, secretKey) => {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { userId, exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 30) };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    const signature = require('crypto').createHmac('sha256', secretKey).update(`${encodedHeader}.${encodedPayload}`).digest('base64');
    return `${encodedHeader}.${encodedPayload}.${signature}`;
};

const verifyToken = (token, secretKey) => {
    try {
        const [encodedHeader, encodedPayload, signature] = token.split('.');
        const expectedSignature = require('crypto').createHmac('sha256', secretKey).update(`${encodedHeader}.${encodedPayload}`).digest('base64');
        if (signature !== expectedSignature) return null;
        const payload = JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
        if (payload.exp < Math.floor(Date.now() / 1000)) return null;
        return payload;
    } catch (err) {
        return null;
    }
};

const server = http.createServer(async (req, res) => {
    const { pathname } = url.parse(req.url);
    let SECRET_KEY;
    try {
        SECRET_KEY = await get('secret_key');
        if (!SECRET_KEY) throw new Error('SECRET_KEY not found');
    } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(`${err.cause} ${err.stack} ${err.path} ${err.message}`);
        return;
    }

    if (pathname === '/' && req.method === 'GET') {
        fs.readFile(path.resolve('./index.html'), 'utf8', (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`${err.cause} ${err.stack} ${err.path} ${err.message}`);
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (pathname === '/login' && req.method === 'POST') {
        let body = '';
        req.on('data', (chunk) => body += chunk.toString());
        req.on('end', async () => {
            const { username, password } = querystring.parse(body);
            try {
                const loginConfig = await get('login');
                if (!loginConfig || !loginConfig.username || !loginConfig.password) throw new Error('Login config not found');
                if (username === loginConfig.username && password === loginConfig.password) {
                    const token = generateToken(1, SECRET_KEY);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ token }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid credentials' }));
                }
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Internal Server Error' }));
            }
        });
    } else if (pathname === '/protected' && req.method === 'GET') {
        const token = req.headers.authorization?.split(' ')[1];
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
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

const PORT = process.env.PORT || 3006;
server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}/`));