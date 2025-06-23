document.addEventListener('DOMContentLoaded', () => {
    // Application state
    const state = {
        isConnected: false,
        currentServer: null,
        terminalInitialized: false
    };
    
    // DOM element references
    const elements = {
        // Tab related
        tabButtons: document.querySelectorAll('.tab-button'),
        tabContents: document.querySelectorAll('.tab-content'),
        tabs: document.querySelector('.tabs'),
        
        // Server related
        addServerForm: document.getElementById('add-server-form'),
        serverList: document.getElementById('server-list'),
        noServersMessage: document.getElementById('no-servers-message'),
        
        // Connection related
        connectionForm: document.getElementById('connection-form'),
        terminalContainer: document.getElementById('terminal-container'),
        connectButton: document.getElementById('connect-button'),
        backButton: document.getElementById('back-button'),
        disconnectButton: document.getElementById('disconnect-button'),
        serverNameDisplay: document.getElementById('server-name-display'),
        serverHostDisplay: document.getElementById('server-host-display'),
        serverUsernameDisplay: document.getElementById('server-username-display'),
        terminalServerName: document.getElementById('terminal-server-name'),
        
        // Authentication related
        loginForm: document.getElementById('login-form'),
        loginContainer: document.getElementById('login-container'),
        appContainer: document.getElementById('app-container'),
        logoutButton: document.getElementById('logout-button'),
        usernameDisplay: document.getElementById('username-display'),
        
        // Password change related
        changePasswordButton: document.getElementById('change-password-button'),
        changePasswordContainer: document.getElementById('change-password-container'),
        changePasswordForm: document.getElementById('change-password-form'),
        cancelPasswordButton: document.getElementById('cancel-password-button'),
        
        // Others
        statusMessage: document.getElementById('status-message'),
        darkModeToggle: document.getElementById('dark-mode-toggle')
    };
    
    // Utility functions
    const utils = {
        // Escape HTML
        escapeHTML: (str) => {
            return str
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        },
        
        // Get CSRF token
        getCsrfToken: () => {
            return document.cookie.split('; ')
                .find(row => row.startsWith('XSRF-TOKEN='))
                ?.split('=')[1];
        },
        
        // Show status message
        showStatus: (message, type = 'info') => {
            elements.statusMessage.textContent = message;
            elements.statusMessage.className = type;
            
            // Success messages disappear after 5 seconds
            if (type === 'success') {
                setTimeout(() => {
                    elements.statusMessage.textContent = '';
                    elements.statusMessage.className = '';
                }, 5000);
            }
        },
        
        // Send API request
        fetchAPI: async (url, options = {}) => {
            try {
                const response = await fetch(url, options);
                
                // If authentication error
                if (response.status === 401) {
                    auth.checkStatus();
                    return { error: 'Authentication required' };
                }
                
                const data = await response.json();
                return { response, data };
            } catch (err) {
                console.error(`API error (${url}):`, err);
                return { error: err.message };
            }
        }
    };
    
    
    // Initialize socket.io with secure connection
    const socket = io({
        secure: true,
        rejectUnauthorized: false // Allow self-signed certificates (development only)
    });
    
    // Initialize xterm.js
    const term = new Terminal({
        cursorBlink: true,
        theme: {
            background: '#000000',
            foreground: '#ffffff'
        },
        rows: 24,
        cols: 80,
        scrollback: 1000,  // Set scrollback buffer size
        convertEol: true   // Convert line endings
    });
    
    // Use FitAddon to automatically adjust terminal size
    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    
    // Old variables removed (replaced with state.isConnected, state.currentServer, state.terminalInitialized)
    
    // UI management
    const ui = {
        // Switch tab
        switchTab: (tabId) => {
            // Hide all tab contents
            elements.tabContents.forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active state from all tab buttons
            elements.tabButtons.forEach(button => {
                button.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabId).classList.add('active');
            document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');
        },
        
        // Show tabs
        showTabs: () => {
            elements.tabs.style.display = 'flex';
        },
        
        // Hide tabs
        hideTabs: () => {
            elements.tabs.style.display = 'none';
        },
        
        // Show connection form
        showConnectionForm: () => {
            elements.connectionForm.classList.remove('hidden');
        },
        
        // Hide connection form
        hideConnectionForm: () => {
            elements.connectionForm.classList.add('hidden');
        },
        
        // Show terminal
        showTerminal: () => {
            elements.terminalContainer.classList.remove('hidden');
        },
        
        // Hide terminal
        hideTerminal: () => {
            elements.terminalContainer.classList.add('hidden');
        },
        
        // Show password change form
        showPasswordForm: (forceMode = false) => {
            ui.hideTabs();
            ui.hideConnectionForm();
            // Hide server list
            document.getElementById('servers-tab').classList.remove('active');
            document.getElementById('add-server-tab').classList.remove('active');
            elements.changePasswordContainer.classList.remove('hidden');
            elements.changePasswordForm.reset();
            
            // Disable cancel button in force mode
            if (forceMode && elements.cancelPasswordButton) {
                elements.cancelPasswordButton.disabled = true;
                elements.cancelPasswordButton.style.opacity = '0.5';
            }
        },
        
        // Hide password change form
        hidePasswordForm: () => {
            elements.changePasswordContainer.classList.add('hidden');
            
            // Enable cancel button
            if (elements.cancelPasswordButton) {
                elements.cancelPasswordButton.disabled = false;
                elements.cancelPasswordButton.style.opacity = '1';
            }
        },
        
        // Initialize dark mode (default is dark mode)
        initDarkMode: () => {
            // If darkMode is not set in localStorage, default to true (dark mode)
            const isDarkMode = localStorage.getItem('darkMode') === null ? 
                true : localStorage.getItem('darkMode') === 'true';
            
            // Set localStorage if it's not set yet
            if (localStorage.getItem('darkMode') === null) {
                localStorage.setItem('darkMode', 'true');
            }
            
            if (isDarkMode) {
                document.body.classList.add('dark-mode');
                ui.updateDarkModeButton(true);
            } else {
                document.body.classList.remove('dark-mode');
                ui.updateDarkModeButton(false);
            }
        },
        
        // Update dark mode button
        updateDarkModeButton: (isDarkMode) => {
            if (!elements.darkModeToggle) return;
            
            const iconSpan = elements.darkModeToggle.querySelector('.icon');
            const textSpan = elements.darkModeToggle.querySelector('.text');
            
            if (isDarkMode) {
                iconSpan.textContent = '☀️';
                textSpan.textContent = 'Light Mode';
            } else {
                iconSpan.textContent = '🌙';
                textSpan.textContent = 'Dark Mode';
            }
        },
        
        // Toggle dark mode
        toggleDarkMode: () => {
            const isDarkMode = document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', isDarkMode);
            ui.updateDarkModeButton(isDarkMode);
        }
    };
    
    // Server management
    const servers = {
        // Load server list
        load: async () => {
            const { error, data } = await utils.fetchAPI('/api/servers');
            
            if (error) {
                utils.showStatus('Failed to load servers. Please try again.', 'error');
                return;
            }
            
            // Clear server list
            elements.serverList.innerHTML = '';
            
            if (data.length === 0) {
                // Show message if no servers
                elements.noServersMessage.style.display = 'block';
                return;
            }
            
            // Hide message if servers exist
            elements.noServersMessage.style.display = 'none';
            
            // Add each server to the list
            data.forEach(server => {
                const serverItem = servers.createServerItem(server);
                elements.serverList.appendChild(serverItem);
            });
            
            // Add connect button event listeners
            document.querySelectorAll('.connect-server-button').forEach(button => {
                button.addEventListener('click', () => {
                    const serverId = button.getAttribute('data-id');
                    servers.select(serverId);
                });
            });
            
            // Add delete button event listeners
            document.querySelectorAll('.delete-server-button').forEach(button => {
                button.addEventListener('click', () => {
                    const serverId = button.getAttribute('data-id');
                    servers.delete(serverId);
                });
            });
        },
        
        // Create server item
        createServerItem: (server) => {
            // XSS prevention: Use DOM methods to create elements
            const serverItem = document.createElement('div');
            serverItem.className = 'server-item';
            
            const serverInfo = document.createElement('div');
            serverInfo.className = 'server-info';
            
            const serverName = document.createElement('div');
            serverName.className = 'server-name';
            serverName.textContent = server.name;
            
            const serverHost = document.createElement('div');
            serverHost.className = 'server-host';
            serverHost.textContent = `${server.host} (${server.username})`;
            
            const serverActions = document.createElement('div');
            serverActions.className = 'server-actions';
            
            const connectButton = document.createElement('button');
            connectButton.className = 'connect-server-button';
            connectButton.textContent = 'Connect';
            connectButton.setAttribute('data-id', server.id);
            
            const deleteButton = document.createElement('button');
            deleteButton.className = 'delete-server-button delete-button';
            deleteButton.textContent = 'Delete';
            deleteButton.setAttribute('data-id', server.id);
            
            // Assemble elements
            serverInfo.appendChild(serverName);
            serverInfo.appendChild(serverHost);
            
            serverActions.appendChild(connectButton);
            serverActions.appendChild(deleteButton);
            
            serverItem.appendChild(serverInfo);
            serverItem.appendChild(serverActions);
            
            return serverItem;
        },
        
        // Select server
        select: async (serverId) => {
            const { error, data } = await utils.fetchAPI(`/api/servers/${serverId}`);
            
            if (error) {
                utils.showStatus('Failed to load server details. Please try again.', 'error');
                return;
            }
            
            // Save current server
            state.currentServer = data;
            
            // Update connection form
            elements.serverNameDisplay.textContent = data.name;
            elements.serverHostDisplay.textContent = data.host;
            elements.serverUsernameDisplay.textContent = data.username;
            
            // Hide tabs, show connection form
            ui.hideTabs();
            ui.showConnectionForm();
        },
        
        // Delete server
        delete: async (serverId) => {
            if (confirm('Are you sure you want to delete this server?')) {
                const { error, data, response } = await utils.fetchAPI(`/api/servers/${serverId}`, {
                    method: 'DELETE',
                    headers: {
                        'CSRF-Token': utils.getCsrfToken()
                    }
                });
                
                if (error) {
                    utils.showStatus('Failed to delete server. Please try again.', 'error');
                    return;
                }
                
                if (response && response.ok) {
                    utils.showStatus('Server deleted successfully.', 'success');
                    servers.load();
                } else if (data && data.error) {
                    utils.showStatus(`Error: ${data.error}`, 'error');
                }
            }
        }
    };
    
    // Authentication management
    const auth = {
        // Check authentication status
        checkStatus: async () => {
            try {
                const response = await fetch('/api/auth-status');
                const data = await response.json();
                
                if (data.authenticated) {
                    // Display username
                    if (elements.usernameDisplay) {
                        elements.usernameDisplay.textContent = data.user.username;
                    }
                    
                    // Show app
                    elements.loginContainer.classList.add('hidden');
                    elements.appContainer.classList.remove('hidden');
                    
                    // Force password change if using default password
                    if (data.user.isDefaultPassword) {
                        auth.forcePasswordChange();
                    } else {
                        // Load server list
                        servers.load();
                    }
                } else {
                    // Show login form
                    elements.loginContainer.classList.remove('hidden');
                    elements.appContainer.classList.add('hidden');
                }
            } catch (err) {
                console.error('Error checking auth status:', err);
                utils.showStatus('Failed to check authentication status.', 'error');
            }
        },
        
        // Force default password change
        forcePasswordChange: () => {
            ui.showPasswordForm(true);
            utils.showStatus('You are using the default password. For security reasons, please change your password.', 'error');
        }
    };
    
    // SSH connection management
    const ssh = {
        // Start SSH connection
        connect: (serverId) => {
            utils.showStatus('Connecting to SSH server...', 'info');
            
            // Send only server ID (don't send private key)
            socket.emit('ssh-connect', { serverId });
        },
        
        // Disconnect SSH connection
        disconnect: () => {
            if (state.isConnected) {
                socket.disconnect();
                state.isConnected = false;
                
                // Hide terminal, show tabs
                ui.hideTerminal();
                ui.showTabs();
                ui.switchTab('servers-tab');
                
                utils.showStatus('Disconnected from SSH server.', 'info');
                
                // Reconnect socket for future connections
                socket.connect();
            }
        },
        
        // Initialize terminal
        initTerminal: () => {
            if (!state.terminalInitialized) {
                term.open(document.getElementById('terminal'));
                
                // Auto-adjust terminal size
                try {
                    fitAddon.fit();
                } catch (e) {
                    console.error('Error fitting terminal:', e);
                }
                
                // Adjust terminal size on window resize
                window.addEventListener('resize', () => {
                    try {
                        fitAddon.fit();
                    } catch (e) {
                        console.error('Error fitting terminal on resize:', e);
                    }
                });
                
                // Process user input
                term.onData(data => {
                    if (state.isConnected) {
                        socket.emit('ssh-data', data);
                    }
                });
                
                // Enable terminal scrolling
                term.attachCustomKeyEventHandler((event) => {
                    // Scroll with PageUp/PageDown keys
                    if (event.type === 'keydown') {
                        if (event.key === 'PageUp') {
                            term.scrollLines(-term.rows);
                            return false;
                        } else if (event.key === 'PageDown') {
                            term.scrollLines(term.rows);
                            return false;
                        }
                    }
                    return true;
                });
                
                state.terminalInitialized = true;
            }
            
            term.focus();
        }
    };
    
    // Tab button click event
    elements.tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            ui.switchTab(tabId);
        });
    });
    
    // Add server form submission
    elements.addServerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const name = document.getElementById('server-name').value;
        const host = document.getElementById('server-host').value;
        const username = document.getElementById('server-username').value;
        const privateKey = document.getElementById('server-private-key').value;
        
        try {
            const response = await fetch('/api/servers', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'CSRF-Token': utils.getCsrfToken()
                },
                body: JSON.stringify({
                    name,
                    host,
                    username,
                    privateKey
                })
            });
            
            if (response.status === 401) {
                // Authentication required
                auth.checkStatus();
                return;
            }
            
            if (response.ok) {
                utils.showStatus('Server added successfully!', 'success');
                
                // Clear form
                elements.addServerForm.reset();
                
                // Switch to servers tab
                ui.switchTab('servers-tab');
                
                // Reload servers
                servers.load();
            } else {
                const data = await response.json();
                utils.showStatus(`Error: ${data.error}`, 'error');
            }
        } catch (err) {
            console.error('Error adding server:', err);
            utils.showStatus('Failed to add server. Please try again.', 'error');
        }
    });
    
    // Login form submission
    if (elements.loginForm) {
        // Get login error message element reference
        const loginErrorElement = document.getElementById('login-error');
        
        // Function to show/hide login error message
        const showLoginError = (show = true) => {
            if (show) {
                loginErrorElement.classList.remove('hidden');
            } else {
                loginErrorElement.classList.add('hidden');
            }
        };
        
        // Hide error message initially
        showLoginError(false);
        
        elements.loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            // Hide error message before submission
            showLoginError(false);
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': utils.getCsrfToken()
                    },
                    body: JSON.stringify({
                        username,
                        password
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.success) {
                        // Login successful
                        elements.loginForm.reset();
                        
                        // Redirect to target URL if available
                        console.log('Login successful, redirect URL:', data.redirectTo);
                        if (data.redirectTo) {
                            console.log('Redirecting to:', data.redirectTo);
                            window.location.href = data.redirectTo;
                            return;
                        }
                        
                        auth.checkStatus();
                    } else {
                        // Login failed - show error message
                        showLoginError(true);
                    }
                } else {
                    // API error - show error message
                    showLoginError(true);
                    const data = await response.json();
                    utils.showStatus(`Error: ${data.error}`, 'error');
                }
            } catch (err) {
                console.error('Error logging in:', err);
                // Communication error - show error message
                showLoginError(true);
                utils.showStatus('Failed to login. Please try again.', 'error');
            }
        });
    }
    
    // Logout button click event
    if (elements.logoutButton) {
        elements.logoutButton.addEventListener('click', async () => {
            try {
                const response = await fetch('/api/logout', {
                    method: 'POST',
                    headers: {
                        'CSRF-Token': utils.getCsrfToken()
                    }
                });
                
                if (response.ok) {
                    // Logout successful
                    auth.checkStatus();
                } else {
                    const data = await response.json();
                    utils.showStatus(`Error: ${data.error}`, 'error');
                }
            } catch (err) {
                console.error('Error logging out:', err);
                utils.showStatus('Failed to logout. Please try again.', 'error');
            }
        });
    }
    
    // Password change button click event
    if (elements.changePasswordButton) {
        elements.changePasswordButton.addEventListener('click', () => {
            ui.showPasswordForm(false);
        });
    }
    
    // Password change cancel button click event
    if (elements.cancelPasswordButton) {
        elements.cancelPasswordButton.addEventListener('click', () => {
            ui.hidePasswordForm();
            ui.showTabs();
            ui.switchTab('servers-tab');
        });
    }
    
    // Password change form submission event
    if (elements.changePasswordForm) {
        elements.changePasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const currentPassword = document.getElementById('current-password').value;
            const newPassword = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            
            // Check if new password and confirmation match
            if (newPassword !== confirmPassword) {
                utils.showStatus('New passwords do not match.', 'error');
                return;
            }
            
            // Check if new password is different from current password
            if (currentPassword === newPassword) {
                utils.showStatus('New password must be different from the current password.', 'error');
                return;
            }
            
            try {
                const response = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'CSRF-Token': utils.getCsrfToken()
                    },
                    body: JSON.stringify({
                        currentPassword,
                        newPassword
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.success) {
                        // Password change successful
                        utils.showStatus('Password changed successfully!', 'success');
                        
                        // Hide password change form
                        ui.hidePasswordForm();
                        
                        // Show tabs and server list
                        ui.showTabs();
                        ui.switchTab('servers-tab');
                        
                        // Load server list
                        servers.load();
                    } else {
                        utils.showStatus(`Error: ${data.error}`, 'error');
                    }
                } else {
                    const data = await response.json();
                    utils.showStatus(`Error: ${data.error}`, 'error');
                }
            } catch (err) {
                console.error('Error changing password:', err);
                utils.showStatus('Failed to change password. Please try again.', 'error');
            }
        });
    }
    
    // Connect button click event
    elements.connectButton.addEventListener('click', () => {
        if (state.currentServer) {
            // Open terminal screen in new window
            const terminalUrl = `/terminal?id=${state.currentServer.id}&name=${encodeURIComponent(state.currentServer.name)}`;
            window.open(terminalUrl, '_blank');
            
            // Hide connection form and show tabs
            ui.hideConnectionForm();
            ui.showTabs();
            ui.switchTab('servers-tab');
        }
    });
    
    // Back button click event
    elements.backButton.addEventListener('click', () => {
        // Hide connection form, show tabs and server list
        ui.hideConnectionForm();
        ui.showTabs();
        ui.switchTab('servers-tab');
    });
    
    // Disconnect button click event
    elements.disconnectButton.addEventListener('click', () => ssh.disconnect());
    
    // Socket.io event handlers
    
    // Connected to SSH server
    socket.on('ssh-connected', () => {
        state.isConnected = true;
        utils.showStatus('Connected to SSH server!', 'success');
    });
    
    // Received data from SSH server
    socket.on('ssh-data', (data) => {
        term.write(data);
    });
    
    // SSH connection error
    socket.on('ssh-error', (data) => {
        utils.showStatus(`Error: ${data.message}`, 'error');
        
        // Hide terminal, show tabs and server list
        ui.hideTerminal();
        ui.showTabs();
        ui.switchTab('servers-tab');
    });
    
    // SSH connection closed
    socket.on('ssh-closed', () => {
        state.isConnected = false;
        utils.showStatus('SSH connection closed.', 'info');
        
        // Hide terminal, show tabs and server list
        ui.hideTerminal();
        ui.showTabs();
        ui.switchTab('servers-tab');
    });
    
    // Socket disconnected
    socket.on('disconnect', () => {
        state.isConnected = false;
        utils.showStatus('Disconnected from server.', 'error');
        
        // Hide terminal, show tabs and server list
        ui.hideTerminal();
        ui.showTabs();
        ui.switchTab('servers-tab');
    });
    
    // Handle page unload
    window.addEventListener('beforeunload', () => {
        if (state.isConnected) {
            socket.disconnect();
        }
    });
    
    // Dark mode toggle button click event
    if (elements.darkModeToggle) {
        elements.darkModeToggle.addEventListener('click', ui.toggleDarkMode);
    }
    
    // Initialize dark mode
    ui.initDarkMode();
    
    // Check authentication status on initialization
    if (elements.loginContainer && elements.appContainer) {
        auth.checkStatus();
    } else {
        // Load server list directly if no authentication feature
        servers.load();
    }
});
