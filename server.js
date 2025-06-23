const express = require('express');
const https = require('https');
const socketIo = require('socket.io');
const { Client } = require('ssh2');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const csrf = require('@dr.pogodin/csurf');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const db = require('./models');

const app = express();

// SSL/TLS certificate paths
const certPath = path.join(__dirname, 'certs/cert.pem');
const keyPath = path.join(__dirname, 'certs/key.pem');
const certsDir = path.join(__dirname, 'certs');

// Function to generate self-signed certificate
function generateSelfSignedCertificate() {
  console.log('SSL certificate not found. Generating self-signed certificate...');
  
  // Create certs directory if it doesn't exist
  if (!fs.existsSync(certsDir)) {
    fs.mkdirSync(certsDir, { recursive: true });
  }
  
  // Use OpenSSL commands to generate self-signed certificate
  const { execSync } = require('child_process');
  
  try {
    // Generate private key
    execSync(`openssl genrsa -out "${keyPath}" 2048`);
    
    // Generate certificate signing request (CSR)
    execSync(`openssl req -new -key "${keyPath}" -out "${certsDir}/cert.csr" -subj "/C=JP/ST=Tokyo/L=Tokyo/O=SSH Web Terminal/OU=Development/CN=localhost"`);
    
    // Generate self-signed certificate
    execSync(`openssl x509 -req -days 3650 -in "${certsDir}/cert.csr" -signkey "${keyPath}" -out "${certPath}"`);
    
    // Remove CSR file
    fs.unlinkSync(`${certsDir}/cert.csr`);
    
    console.log('Self-signed certificate generated successfully.');
  } catch (err) {
    console.error('Certificate generation error:', err);
    throw new Error('Failed to generate SSL certificate.');
  }
}

// Check if SSL/TLS certificates exist and load them
if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  generateSelfSignedCertificate();
}

// Load SSL/TLS certificates
const httpsOptions = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath)
};

// Create HTTPS server
const server = https.createServer(httpsOptions, app);
const io = socketIo(server);

// HTTP server is disabled (HTTPS only)

// Encryption settings
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'ssh-web-terminal-encryption-key-12345';
const ENCRYPTION_KEY_BUFFER = Buffer.from(ENCRYPTION_KEY.toString().padEnd(32, '0').slice(0, 32));

// Encryption/decryption utility functions
const crypto_utils = {
  // Encrypt data
  encrypt: (data) => {
    if (!data) return null;
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY_BUFFER, iv);
      const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
      return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (err) {
      console.error('Encryption error:', err);
      return null;
    }
  },
  
  // Decrypt data
  decrypt: (data) => {
    if (!data || !data.includes(':')) return null;
    try {
      const [ivHex, encryptedHex] = data.split(':');
      const iv = Buffer.from(ivHex, 'hex');
      const encryptedText = Buffer.from(encryptedHex, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY_BUFFER, iv);
      return Buffer.concat([decipher.update(encryptedText), decipher.final()]).toString();
    } catch (err) {
      console.error('Decryption error:', err);
      return null;
    }
  }
};

// Input validation functions
const validators = {
  // Validate hostname
  host: (host) => {
    const hostRegex = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    return hostRegex.test(host);
  },
  
  // Validate private key
  privateKey: (key) => key && key.includes('BEGIN') && key.includes('PRIVATE KEY')
};

// Middleware setup
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: true, // Always use secure cookies with HTTPS
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000 // Session timeout: 30 minutes
  }
}));

// Middleware to temporarily store session data
app.use((req, res, next) => {
  // Initialize temporary storage property
  req.sessionStore.tempData = req.sessionStore.tempData || {};
  
  // If redirect URL is in session, also save it to temporary storage
  if (req.session.redirectTo) {
    console.log('Saving redirect URL to temp storage:', req.session.redirectTo);
    req.sessionStore.tempData[req.sessionID] = {
      redirectTo: req.session.redirectTo
    };
  }
  
  // Restore redirect URL from temporary storage if needed
  if (req.sessionStore.tempData[req.sessionID] && !req.session.redirectTo) {
    console.log('Restoring redirect URL from temp storage:', req.sessionStore.tempData[req.sessionID].redirectTo);
    req.session.redirectTo = req.sessionStore.tempData[req.sessionID].redirectTo;
    delete req.sessionStore.tempData[req.sessionID]; // Clean up after use
  }
  
  next();
});

// Passport.js setup
app.use(passport.initialize());
app.use(passport.session());

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Allow 5 requests per 15 minutes
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false, // Disable X-RateLimit-* headers
  message: { error: 'Too many login attempts, please try again after 15 minutes' }
});

// Rate limiting for general API requests
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Allow 100 requests per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again after 15 minutes' }
});

// CSRF protection setup
app.use(csrf({ cookie: true }));

// Include CSRF token in all responses
app.use((req, res, next) => {
  res.cookie('XSRF-TOKEN', req.csrfToken());
  next();
});

// Authentication error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'CSRF token validation failed' });
  }
  next(err);
});

// Terminal route with authentication check
app.get('/terminal', (req, res) => {
  // Save query parameters for redirect after login
  const queryParams = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
  
  // Redirect to login page if not authenticated
  if (!req.isAuthenticated()) {
    console.log('Unauthenticated user accessed terminal. Saving redirect URL:', `/terminal${queryParams}`);
    // Save redirect URL to session
    req.session.redirectTo = `/terminal${queryParams}`;
    // Ensure session is saved before redirect
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
      }
      return res.redirect('/');
    });
    return;
  }
  
  res.sendFile(path.join(__dirname, 'public/terminal.html'));
});

// Passport.js configuration
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await db.User.findOne({ where: { username } });
      
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      
      if (!bcrypt.compareSync(password, user.passwordHash)) {
        return done(null, false, { message: 'Incorrect password.' });
      }
      
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.User.findByPk(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware to protect routes that require authentication
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
}

// Login endpoint with rate limiting
app.post('/api/login', loginLimiter, (req, res, next) => {
  // Save session ID before authentication
  const oldSessionID = req.sessionID;
  console.log('Session ID before login:', oldSessionID);
  
  // Execute Passport authentication
  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) { return res.json({ success: false }); }
    
    // Execute login
    req.login(user, (err) => {
      if (err) { return next(err); }
      
      // Reset session expiration
      req.session.cookie.maxAge = 30 * 60 * 1000; // 30 minutes
      
      // Get redirect URL from temporary storage or session
      let redirectTo = null;
      if (req.sessionStore.tempData && req.sessionStore.tempData[oldSessionID]) {
        redirectTo = req.sessionStore.tempData[oldSessionID].redirectTo;
        console.log('Retrieved redirect URL from temp storage:', redirectTo);
        delete req.sessionStore.tempData[oldSessionID];
      } else {
        // Get redirect URL from session
        redirectTo = req.session.redirectTo || null;
        console.log('Retrieved redirect URL from session:', redirectTo);
        delete req.session.redirectTo;
      }
      
      // Ensure session is saved before sending response
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
        }
        
        res.json({ 
          success: true, 
          user: { username: user.username },
          redirectTo: redirectTo
        });
      });
    });
  })(req, res, next);
});

// Logout endpoint with rate limiting
app.post('/api/logout', apiLimiter, (req, res) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.json({ success: true });
  });
});

// Authentication status check endpoint with rate limiting
app.get('/api/auth-status', apiLimiter, (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      authenticated: true, 
      user: { 
        username: req.user.username,
        isDefaultPassword: req.user.isDefaultPassword || false
      } 
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Password change endpoint with rate limiting
app.post('/api/change-password', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Input validation
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }
    
    // New password strength validation
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long' });
    }
    
    // Get user information
    const user = await db.User.findByPk(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Verify current password
    if (!bcrypt.compareSync(currentPassword, user.passwordHash)) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    // Hash and save new password
    user.passwordHash = bcrypt.hashSync(newPassword, 10);
    
    // Remove default password flag
    user.isDefaultPassword = false;
    
    // Save to database
    await user.save();
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// API endpoint to get all servers with rate limiting
app.get('/api/servers', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const servers = await db.Server.findAll();
    // Don't send private keys to the client for security
    const safeServers = servers.map(server => ({
      id: server.id,
      name: server.name,
      host: server.host,
      username: server.username
    }));
    res.json(safeServers);
  } catch (err) {
    console.error('Error reading servers from database:', err);
    res.status(500).json({ error: 'Failed to read servers' });
  }
});

// API endpoint to add a new server with rate limiting
app.post('/api/servers', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const { name, host, username, privateKey } = req.body;
    
    // Input validation
    if (!name || !host || !username || !privateKey) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Hostname format validation
    if (!validators.host(host)) {
      return res.status(400).json({ error: 'Invalid host format' });
    }
    
    // Private key format validation
    if (!validators.privateKey(privateKey)) {
      return res.status(400).json({ error: 'Invalid private key format' });
    }
    
    // Generate a unique ID
    const id = Date.now().toString();
    
    // Encrypt and save private key
    const encryptedPrivateKey = crypto_utils.encrypt(privateKey);
    
    // Add new server to database
    const server = await db.Server.create({
      id,
      name,
      host,
      username,
      privateKey: encryptedPrivateKey
    });
    
    // Return the new server without the private key
    res.status(201).json({
      id: server.id,
      name: server.name,
      host: server.host,
      username: server.username
    });
  } catch (err) {
    console.error('Error adding server:', err);
    res.status(500).json({ error: 'Failed to add server' });
  }
});

// API endpoint to get a server by ID with rate limiting
app.get('/api/servers/:id', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    const server = await db.Server.findByPk(id);
    
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    // Don't send private key (decrypt only when needed for connection)
    const safeServer = {
      id: server.id,
      name: server.name,
      host: server.host,
      username: server.username
    };
    
    res.json(safeServer);
  } catch (err) {
    console.error('Error getting server:', err);
    res.status(500).json({ error: 'Failed to get server' });
  }
});

// API endpoint to delete a server with rate limiting
app.delete('/api/servers/:id', isAuthenticated, apiLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.Server.destroy({ where: { id } });
    
    if (result === 0) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    res.json({ message: 'Server deleted successfully' });
  } catch (err) {
    console.error('Error deleting server:', err);
    res.status(500).json({ error: 'Failed to delete server' });
  }
});

// Socket.io connection
io.on('connection', (socket) => {
  console.log('Client connected');

  // Handle SSH connection request
  socket.on('ssh-connect', async (data) => {
    const { serverId, passphrase } = data;
    
    try {
      // Validate input
      if (!serverId) {
        socket.emit('ssh-error', { message: 'Server ID is required' });
        return;
      }
      
      // Get server information with error handling
      const server = await db.Server.findByPk(serverId);
      if (!server) {
        socket.emit('ssh-error', { message: 'Server not found' });
        return;
      }
      
      // Decrypt private key with improved error handling
      let privateKeyToUse;
      try {
        if (server.privateKey.includes(':')) {
          privateKeyToUse = crypto_utils.decrypt(server.privateKey);
        } else {
          privateKeyToUse = server.privateKey; // Legacy non-encrypted data
        }
        
        if (!privateKeyToUse) {
          throw new Error('Decryption resulted in empty key');
        }
      } catch (decryptError) {
        console.error('Private key decryption error:', decryptError);
        socket.emit('ssh-error', { message: 'Failed to decrypt private key' });
        return;
      }
      
      // Check if private key is passphrase protected with improved detection
      const isEncrypted = 
        privateKeyToUse.includes('ENCRYPTED') || 
        privateKeyToUse.includes('Proc-Type: 4,ENCRYPTED') ||
        privateKeyToUse.includes('DEK-Info:');
      
      // If passphrase is required but not provided
      if (isEncrypted && !passphrase) {
        socket.emit('passphrase-required');
        return;
      }
      
      const ssh = new Client();
    
    // Handle SSH connection errors
    ssh.on('error', (err) => {
      console.error('SSH connection error:', err);
      socket.emit('ssh-error', { message: err.message });
    });
    
    // Connect to SSH server
    ssh.on('ready', () => {
      console.log('SSH connection established');
      socket.emit('ssh-connected');
      
      // Create a new shell session
      ssh.shell((err, stream) => {
        if (err) {
          console.error('SSH shell error:', err);
          socket.emit('ssh-error', { message: err.message });
          return;
        }
        
        // Forward data from SSH to client
        stream.on('data', (data) => {
          socket.emit('ssh-data', data.toString('utf-8'));
        });
        
        // Forward data from client to SSH
        socket.on('ssh-data', (data) => {
          stream.write(data);
        });
        
        // Handle SSH stream close
        stream.on('close', () => {
          console.log('SSH stream closed');
          socket.emit('ssh-closed');
          ssh.end();
        });
      });
    });
    
    // Connect to the SSH server with improved configuration
    try {
      // Create SSH configuration with sensible defaults
      const sshConfig = {
        host: server.host,
        port: 22, // Default SSH port
        username: server.username,
        privateKey: privateKeyToUse,
        readyTimeout: 30000, // 30 seconds connection timeout
        keepaliveInterval: 60000, // Send keepalive every 60 seconds
        keepaliveCountMax: 3, // Allow 3 missed keepalives before disconnecting
        debug: process.env.NODE_ENV === 'development' ? console.log : undefined
      };
      
      // Add passphrase to config if provided
      if (passphrase) {
        sshConfig.passphrase = passphrase;
      }
      
      // Connect with improved error handling
      ssh.connect(sshConfig);
    } catch (err) {
      console.error('SSH connection error:', err);
      socket.emit('ssh-error', { 
        message: err.message || 'Failed to establish SSH connection'
      });
    }
    } catch (err) {
      console.error('Error retrieving server information:', err);
      socket.emit('ssh-error', { message: 'Failed to retrieve server information' });
    }
  });
  
  // Handle client disconnect
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Check if database file exists
const dbFilePath = path.join(__dirname, 'db/ssh_web_terminal.sqlite');
const isNewDatabase = !fs.existsSync(dbFilePath);

// Sync database before starting the server
db.sequelize.sync().then(async () => {
  console.log('Database synchronized successfully');
  
  // Create initial user on first run
  if (isNewDatabase) {
    try {
      console.log('Creating initial admin user...');
      const adminUser = await db.User.create({
        id: Date.now().toString(),
        username: 'admin',
        passwordHash: bcrypt.hashSync('changeme', 10),
        isDefaultPassword: true
      });
      console.log('Initial admin user created. Username: admin, Password: changeme');
    } catch (err) {
      console.error('Error creating initial user:', err);
    }
  }
  
  // Start the server (HTTPS only)
  const HTTPS_PORT = process.env.HTTPS_PORT || 3000;

  server.listen(HTTPS_PORT, () => {
    console.log(`HTTPS Server running on port ${HTTPS_PORT} (HTTP is disabled)`);
  });
}).catch(err => {
  console.error('Database synchronization error:', err);
});
