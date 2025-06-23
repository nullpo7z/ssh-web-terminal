document.addEventListener('DOMContentLoaded', () => {
    // Cache DOM elements for better performance
    const elements = {
        serverName: document.getElementById('server-name'),
        disconnectButton: document.getElementById('disconnect-button'),
        statusMessage: document.getElementById('status-message'),
        terminal: document.getElementById('terminal'),
        passphraseContainer: document.getElementById('passphrase-container'),
        passphraseInput: document.getElementById('key-passphrase'),
        submitPassphraseButton: document.getElementById('submit-passphrase-button'),
        cancelPassphraseButton: document.getElementById('cancel-passphrase-button')
    };
    
    // Centralized application state
    const state = {
        isConnected: false,
        terminalInitialized: false,
        serverId: null,
        serverName: null,
        needsPassphrase: false,
        passphraseAttempts: 0
    };
    
    // Get server information from URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    state.serverId = urlParams.get('id');
    state.serverName = urlParams.get('name');
    
    if (!state.serverId) {
        showStatus('Server ID not specified', 'error');
        setTimeout(() => {
            window.location.href = '/';
        }, 3000);
        return;
    }
    
    // Display server name
    if (state.serverName) {
        elements.serverName.textContent = state.serverName;
        document.title = `Terminal - ${state.serverName}`;
    }
    
    // Toggle passphrase form visibility
    function togglePassphraseForm(show) {
        if (show) {
            elements.passphraseContainer.classList.add('visible');
            elements.passphraseInput.focus();
            state.needsPassphrase = true;
        } else {
            elements.passphraseContainer.classList.remove('visible');
            elements.passphraseInput.value = '';
        }
    }
    
    // Alias functions for backward compatibility
    const showPassphraseForm = () => togglePassphraseForm(true);
    const hidePassphraseForm = () => togglePassphraseForm(false);
    
    // Enhanced status message display with auto-hide functionality
    function showStatus(message, type = 'info') {
        elements.statusMessage.textContent = message;
        elements.statusMessage.className = type;
        elements.statusMessage.classList.add('visible');
        
        // Auto-hide messages based on type
        const hideDelay = type === 'success' ? 5000 : 
                         type === 'info' ? 10000 : 0; // Don't auto-hide errors
        
        if (hideDelay > 0) {
            setTimeout(() => {
                elements.statusMessage.classList.remove('visible');
            }, hideDelay);
        }
    }
    
    // Initialize dark mode (default is dark mode)
    function initDarkMode() {
        // If darkMode is not set in localStorage, default to true (dark mode)
        const isDarkMode = localStorage.getItem('darkMode') === null ? 
            true : localStorage.getItem('darkMode') === 'true';
        
        // Set localStorage if it's not set yet
        if (localStorage.getItem('darkMode') === null) {
            localStorage.setItem('darkMode', 'true');
        }
        
        if (isDarkMode) {
            document.body.classList.add('dark-mode');
        } else {
            document.body.classList.remove('dark-mode');
        }
    }
    
    // Initialize dark mode
    initDarkMode();
    
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
    
    // Initialize terminal
    function initTerminal() {
        if (!state.terminalInitialized) {
            term.open(elements.terminal);
            
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
    
    // Start SSH connection with improved error handling
    function connectSSH(passphrase = null) {
        if (!state.serverId) {
            showStatus('Server ID not specified', 'error');
            return false;
        }
        
        showStatus('Connecting to SSH server...', 'info');
        
        // Send server ID and passphrase (if exists)
        socket.emit('ssh-connect', { 
            serverId: state.serverId,
            passphrase: passphrase
        });
        
        return true;
    }
    
    // Disconnect SSH connection
    function disconnectSSH() {
        if (state.isConnected) {
            socket.disconnect();
            state.isConnected = false;
            showStatus('Disconnected from SSH server. Closing window...', 'info');
            
            // Close tab
            setTimeout(() => {
                window.close();
            }, 1000);
        } else {
            window.close();
        }
    }
    
    // Disconnect button click event
    elements.disconnectButton.addEventListener('click', disconnectSSH);
    
    // Passphrase submit handler with validation
    function submitPassphrase() {
        const passphrase = elements.passphraseInput.value.trim();
        if (!passphrase) {
            showStatus('Please enter a passphrase', 'error');
            elements.passphraseInput.focus();
            return;
        }
        
        hidePassphraseForm();
        connectSSH(passphrase);
    }
    
    // Passphrase submit button event listener
    elements.submitPassphraseButton.addEventListener('click', submitPassphrase);
    
    // Passphrase cancel button event listener
    elements.cancelPassphraseButton.addEventListener('click', () => {
        hidePassphraseForm();
        showStatus('Connection cancelled', 'info');
        
        // Close tab
        setTimeout(() => {
            window.close();
        }, 1000);
    });
    
    // Handle Enter key press in passphrase input form
    elements.passphraseInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            submitPassphrase();
        }
    });
    
    // Socket.io event handlers
    
    // Connected to SSH server
    socket.on('ssh-connected', () => {
        state.isConnected = true;
        hidePassphraseForm();
        showStatus('Connected to SSH server!', 'success');
    });
    
    // Received data from SSH server
    socket.on('ssh-data', (data) => {
        term.write(data);
    });
    
    // Enhanced SSH connection error handling
    socket.on('ssh-error', (data) => {
        const errorMsg = data.message || 'Unknown error';
        const isPassphraseError = errorMsg.includes('passphrase') || 
                                 errorMsg.includes('authentication') || 
                                 errorMsg.includes('All configured authentication methods failed');
        
        if (isPassphraseError) {
            state.passphraseAttempts++;
            
            // Abort connection after 3 failed attempts
            if (state.passphraseAttempts >= 3) {
                showStatus('Failed to enter correct passphrase 3 times. Aborting connection.', 'error');
                setTimeout(() => {
                    window.close();
                }, 3000);
                return;
            }
            
            showStatus(`Incorrect passphrase (attempt ${state.passphraseAttempts}/3). Please try again.`, 'error');
            showPassphraseForm();
            return;
        }
        
        showStatus(`Connection error: ${errorMsg}. Closing window...`, 'error');
        
        // Close tab
        setTimeout(() => {
            window.close();
        }, 3000);
    });
    
    // SSH connection closed
    socket.on('ssh-closed', () => {
        state.isConnected = false;
        showStatus('SSH connection closed. Closing window...', 'info');
        
        // Close tab
        setTimeout(() => {
            window.close();
        }, 1000);
    });
    
    // Socket disconnected
    socket.on('disconnect', () => {
        state.isConnected = false;
        showStatus('Disconnected from server. Closing window...', 'error');
        
        // Close tab
        setTimeout(() => {
            window.close();
        }, 2000);
    });
    
    // Handle page unload
    window.addEventListener('beforeunload', (event) => {
        if (state.isConnected) {
            // Show confirmation dialog if connected
            event.preventDefault();
            event.returnValue = '';
            
            // Disconnect
            socket.disconnect();
        }
    });
    
    // Event to check if passphrase is required
    socket.on('passphrase-required', () => {
        showPassphraseForm();
    });
    
    // Initialize terminal and connect
    initTerminal();
    connectSSH();
});
