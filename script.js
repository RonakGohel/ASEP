// ============================================================================
// ASEP - Advanced Secure Password Manager
// Improved Version with Enhanced Security
// ============================================================================

// --- 1. CONFIGURATION & CONSTANTS ---

const CONFIG = {
    PASSWORD_LENGTH: 16,
    MIN_CONSTRAINTS: 1,
    MAX_CONSTRAINTS: 5,
    CHARSET: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}|;:,.<>?",
    DEFAULT_PASSWORD_TEXT: 'Click "Generate"',
    STORAGE_KEYS: {
        PASSWORD_MANAGER: 'passwordManager',
        SESSION_EMAIL: 'currentUserEmail',
        SESSION_KEY_HASH: 'masterKeyHash',
        PASSWORD_CONSTRAINTS: 'passwordConstraints'
    },
    PAGES: {
        LOGIN: 'PG-2.html',
        HOME: 'Home_Page.html',
        GENERATOR: 'password_generator.html',
        MANAGER: 'password_manager.html',
        CONSTRAINTS: 'Constraints.html',
        INDEX: 'index.html'
    }
};

// --- 2. CRYPTOGRAPHY MODULE (Enhanced Security) ---

const CryptoModule = {
    /**
     * Generate cryptographically secure random integer
     * @param {number} max - Maximum value (exclusive)
     * @returns {number} - Secure random integer
     */
    getSecureRandomInt(max) {
        const array = new Uint32Array(1);
        crypto.getRandomValues(array);
        return array[0] % max;
    },

    /**
     * Generate cryptographically secure random bytes
     * @param {number} length - Number of bytes
     * @returns {Uint8Array} - Random bytes
     */
    getSecureRandomBytes(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    },

    /**
     * Hash a string using SHA-256
     * @param {string} text - Text to hash
     * @returns {Promise<string>} - Hex string of hash
     */
    async hashSHA256(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    /**
     * Derive encryption key from master password using PBKDF2
     * @param {string} password - Master password
     * @param {Uint8Array} salt - Salt for key derivation
     * @returns {Promise<CryptoKey>} - Derived encryption key
     */
    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    /**
     * Encrypt text using AES-GCM
     * @param {string} text - Text to encrypt
     * @param {string} masterPassword - Master password
     * @returns {Promise<string>} - Base64 encoded encrypted data with salt and IV
     */
    async encrypt(text, masterPassword) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(text);
            
            // Generate random salt and IV
            const salt = this.getSecureRandomBytes(16);
            const iv = this.getSecureRandomBytes(12);
            
            // Derive key from password
            const key = await this.deriveKey(masterPassword, salt);
            
            // Encrypt
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                data
            );
            
            // Combine salt + iv + encrypted data
            const encryptedArray = new Uint8Array(encryptedBuffer);
            const combined = new Uint8Array(salt.length + iv.length + encryptedArray.length);
            combined.set(salt, 0);
            combined.set(iv, salt.length);
            combined.set(encryptedArray, salt.length + iv.length);
            
            // Convert to base64
            return btoa(String.fromCharCode.apply(null, combined));
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt data');
        }
    },

    /**
     * Decrypt text using AES-GCM
     * @param {string} encryptedBase64 - Base64 encoded encrypted data
     * @param {string} masterPassword - Master password
     * @returns {Promise<string>} - Decrypted text
     */
    async decrypt(encryptedBase64, masterPassword) {
        try {
            // Decode from base64
            const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
            
            // Extract salt, iv, and encrypted data
            const salt = combined.slice(0, 16);
            const iv = combined.slice(16, 28);
            const encryptedData = combined.slice(28);
            
            // Derive key
            const key = await this.deriveKey(masterPassword, salt);
            
            // Decrypt
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encryptedData
            );
            
            const decoder = new TextDecoder();
            return decoder.decode(decryptedBuffer);
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt data - incorrect password or corrupted data');
        }
    },

    /**
     * Simple fallback encryption for older browsers (still XOR but improved)
     * Only used if Web Crypto API is unavailable
     */
    fallbackEncrypt(text, key) {
        console.warn('Using fallback encryption - not cryptographically secure');
        return text.split('').map((char, i) => 
            String.fromCharCode(char.charCodeAt(0) ^ key.charCodeAt(i % key.length))
        ).join('');
    }
};

// --- 3. VALIDATION MODULE ---

const Validator = {
    /**
     * Sanitize HTML to prevent XSS
     * @param {string} str - String to sanitize
     * @returns {string} - Sanitized string
     */
    sanitizeHTML(str) {
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    },

    /**
     * Validate website name
     * @param {string} website - Website name
     * @returns {Object} - {valid: boolean, error: string}
     */
    validateWebsite(website) {
        if (!website || website.trim().length === 0) {
            return { valid: false, error: 'Website name cannot be empty' };
        }
        if (website.length > 100) {
            return { valid: false, error: 'Website name too long (max 100 characters)' };
        }
        return { valid: true, error: null };
    },

    /**
     * Validate constraint count
     * @param {number} count - Number of constraints
     * @returns {Object} - {valid: boolean, error: string}
     */
    validateConstraintCount(count) {
        if (isNaN(count)) {
            return { valid: false, error: 'Please enter a valid number' };
        }
        if (count < CONFIG.MIN_CONSTRAINTS || count > CONFIG.MAX_CONSTRAINTS) {
            return { valid: false, error: `Please enter a number between ${CONFIG.MIN_CONSTRAINTS} and ${CONFIG.MAX_CONSTRAINTS}` };
        }
        return { valid: true, error: null };
    },

    /**
     * Validate master password strength
     * @param {string} password - Master password
     * @returns {Object} - {valid: boolean, error: string, strength: string}
     */
    validateMasterPassword(password) {
        if (!password || password.length < 8) {
            return { valid: false, error: 'Master password must be at least 8 characters', strength: 'weak' };
        }
        
        let strength = 0;
        if (password.length >= 12) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^a-zA-Z0-9]/.test(password)) strength++;
        
        const strengthLevel = strength < 3 ? 'weak' : strength < 4 ? 'medium' : 'strong';
        
        if (strength < 3) {
            return { 
                valid: false, 
                error: 'Password too weak. Include uppercase, lowercase, numbers, and symbols', 
                strength: strengthLevel 
            };
        }
        
        return { valid: true, error: null, strength: strengthLevel };
    }
};

// --- 4. STORAGE MODULE (Enhanced with Error Handling) ---

const StorageModule = {
    /**
     * Safely get item from localStorage with error handling
     * @param {string} key - Storage key
     * @param {*} defaultValue - Default value if key doesn't exist
     * @returns {*} - Parsed value or default
     */
    getItem(key, defaultValue = null) {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (error) {
            console.error(`Error reading ${key} from storage:`, error);
            return defaultValue;
        }
    },

    /**
     * Safely set item in localStorage with error handling
     * @param {string} key - Storage key
     * @param {*} value - Value to store
     * @returns {boolean} - Success status
     */
    setItem(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch (error) {
            console.error(`Error writing ${key} to storage:`, error);
            if (error.name === 'QuotaExceededError') {
                alert('Storage quota exceeded. Please delete some passwords.');
            }
            return false;
        }
    },

    /**
     * Get session data
     * @param {string} key - Session key
     * @returns {string|null} - Session value
     */
    getSession(key) {
        return sessionStorage.getItem(key);
    },

    /**
     * Set session data
     * @param {string} key - Session key
     * @param {string} value - Value to store
     */
    setSession(key, value) {
        sessionStorage.setItem(key, value);
    },

    /**
     * Clear all session data
     */
    clearSession() {
        sessionStorage.clear();
    }
};

// --- 5. PASSWORD GENERATION MODULE ---

const PasswordGenerator = {
    /**
     * Generate secure random password
     * @param {Array<string>} constraints - Required strings to include
     * @param {number} length - Total password length
     * @returns {string} - Generated password
     */
    generate(constraints = [], length = CONFIG.PASSWORD_LENGTH) {
        const baseLength = constraints.reduce((sum, c) => sum + c.length, 0);
        
        if (baseLength >= length) {
            alert('Constraints too long! Redirecting...');
            window.location.href = CONFIG.PAGES.CONSTRAINTS;
            return '';
        }

        const remainingLength = length - baseLength;
        const pool = [];
        
        // Generate random characters using secure random
        for (let i = 0; i < remainingLength; i++) {
            const randomIndex = CryptoModule.getSecureRandomInt(CONFIG.CHARSET.length);
            pool.push(CONFIG.CHARSET[randomIndex]);
        }

        // Combine constraints and random characters
        const result = [...constraints, ...pool];
        
        // Fisher-Yates shuffle with secure random
        for (let i = result.length - 1; i > 0; i--) {
            const j = CryptoModule.getSecureRandomInt(i + 1);
            [result[i], result[j]] = [result[j], result[i]];
        }
        
        return result.join('');
    },

    /**
     * Calculate password strength
     * @param {string} password - Password to analyze
     * @returns {Object} - {score: number, level: string, feedback: string}
     */
    calculateStrength(password) {
        let score = 0;
        const feedback = [];

        // Length check
        if (password.length >= 12) {
            score += 2;
        } else if (password.length >= 8) {
            score += 1;
            feedback.push('Increase length to 12+ characters');
        } else {
            feedback.push('Password too short (min 8 characters)');
        }

        // Character variety
        if (/[a-z]/.test(password)) score++;
        else feedback.push('Add lowercase letters');
        
        if (/[A-Z]/.test(password)) score++;
        else feedback.push('Add uppercase letters');
        
        if (/[0-9]/.test(password)) score++;
        else feedback.push('Add numbers');
        
        if (/[^a-zA-Z0-9]/.test(password)) score++;
        else feedback.push('Add special characters');

        // Determine level
        let level;
        if (score <= 2) level = 'Weak';
        else if (score <= 4) level = 'Medium';
        else if (score <= 6) level = 'Strong';
        else level = 'Very Strong';

        return {
            score,
            level,
            feedback: feedback.join(', ')
        };
    }
};

// --- 6. PASSWORD MANAGER MODULE ---

const PasswordManager = {
    /**
     * Get current user credentials from session
     * @returns {Object|null} - {email: string, masterKeyHash: string}
     */
    getCurrentUser() {
        const email = StorageModule.getSession(CONFIG.STORAGE_KEYS.SESSION_EMAIL);
        const keyHash = StorageModule.getSession(CONFIG.STORAGE_KEYS.SESSION_KEY_HASH);
        
        if (!email || !keyHash) {
            return null;
        }
        
        return { email, masterKeyHash: keyHash };
    },

    /**
     * Verify master password
     * @param {string} inputPassword - Password to verify
     * @returns {Promise<boolean>} - Verification result
     */
    async verifyMasterPassword(inputPassword) {
        const user = this.getCurrentUser();
        if (!user) return false;
        
        const inputHash = await CryptoModule.hashSHA256(inputPassword);
        return inputHash === user.masterKeyHash;
    },

    /**
     * Save password to vault
     * @param {string} website - Website name
     * @param {string} password - Password to save
     * @param {string} masterPassword - Master password for encryption
     * @returns {Promise<boolean>} - Success status
     */
    async save(website, password, masterPassword) {
        try {
            const user = this.getCurrentUser();
            if (!user) {
                alert('Please login first to save passwords.');
                window.location.href = CONFIG.PAGES.LOGIN;
                return false;
            }

            // Validate inputs
            const websiteValidation = Validator.validateWebsite(website);
            if (!websiteValidation.valid) {
                alert(websiteValidation.error);
                return false;
            }

            if (!password || password === CONFIG.DEFAULT_PASSWORD_TEXT) {
                alert('Please generate a password first.');
                return false;
            }

            // Verify master password
            const isValid = await this.verifyMasterPassword(masterPassword);
            if (!isValid) {
                alert('Incorrect Master Password. Access denied.');
                return false;
            }

            // Encrypt password
            const encryptedPassword = await CryptoModule.encrypt(password, masterPassword);

            // Get all credentials and filter
            let allCredentials = StorageModule.getItem(CONFIG.STORAGE_KEYS.PASSWORD_MANAGER, []);
            
            // Remove existing entry (case-insensitive)
            allCredentials = allCredentials.filter(cred => 
                !(cred.website.toLowerCase() === website.toLowerCase() && cred.owner === user.email)
            );

            // Add new entry
            allCredentials.push({
                website: Validator.sanitizeHTML(website),
                password: encryptedPassword,
                timestamp: new Date().toISOString(),
                owner: user.email
            });

            // Save
            const success = StorageModule.setItem(CONFIG.STORAGE_KEYS.PASSWORD_MANAGER, allCredentials);
            
            if (success) {
                alert('✓ Password saved successfully to your vault!');
                window.location.href = CONFIG.PAGES.MANAGER;
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Save error:', error);
            alert('Failed to save password: ' + error.message);
            return false;
        }
    },

    /**
     * Retrieve all passwords for current user
     * @param {string} masterPassword - Master password for decryption
     * @returns {Promise<Array>} - Array of decrypted credentials
     */
    async retrieve(masterPassword) {
        try {
            const user = this.getCurrentUser();
            if (!user) {
                throw new Error('Not logged in');
            }

            // Verify master password
            const isValid = await this.verifyMasterPassword(masterPassword);
            if (!isValid) {
                throw new Error('Invalid master password');
            }

            const allCredentials = StorageModule.getItem(CONFIG.STORAGE_KEYS.PASSWORD_MANAGER, []);
            const userCredentials = allCredentials.filter(cred => cred.owner === user.email);

            // Decrypt passwords
            const decrypted = await Promise.all(
                userCredentials.map(async (cred) => {
                    try {
                        const decryptedPassword = await CryptoModule.decrypt(cred.password, masterPassword);
                        return {
                            website: cred.website,
                            password: decryptedPassword,
                            timestamp: cred.timestamp
                        };
                    } catch (error) {
                        console.error(`Failed to decrypt password for ${cred.website}:`, error);
                        return {
                            website: cred.website,
                            password: '[Decryption Failed]',
                            timestamp: cred.timestamp
                        };
                    }
                })
            );

            return decrypted;
        } catch (error) {
            console.error('Retrieve error:', error);
            throw error;
        }
    },

    /**
     * Delete password from vault
     * @param {string} website - Website to delete (case-insensitive)
     * @returns {boolean} - Success status
     */
    delete(website) {
        try {
            const user = this.getCurrentUser();
            if (!user) return false;

            let allCredentials = StorageModule.getItem(CONFIG.STORAGE_KEYS.PASSWORD_MANAGER, []);
            
            // Filter out the entry (case-insensitive)
            allCredentials = allCredentials.filter(cred => 
                !(cred.website.toLowerCase() === website.toLowerCase() && cred.owner === user.email)
            );

            return StorageModule.setItem(CONFIG.STORAGE_KEYS.PASSWORD_MANAGER, allCredentials);
        } catch (error) {
            console.error('Delete error:', error);
            return false;
        }
    }
};

// --- 7. UI CONTROLLER FUNCTIONS ---

/**
 * Display generated passwords on the page
 */
async function displayGeneratedPasswords() {
    const currentUserEmail = StorageModule.getSession(CONFIG.STORAGE_KEYS.SESSION_EMAIL);
    
    // Get global rules for current user
    let globalRules = [];
    if (currentUserEmail) {
        const userSpecificKey = `globalConstraints_${currentUserEmail}`;
        globalRules = StorageModule.getItem(userSpecificKey, []);
    }

    // Get session rules
    const sessionRules = StorageModule.getItem(CONFIG.STORAGE_KEYS.PASSWORD_CONSTRAINTS, []);

    // Combine and deduplicate
    const allConstraints = [...new Set([...globalRules, ...sessionRules])];

    // Display constraints
    const displayElement = document.getElementById('constraintsUsed');
    if (displayElement) {
        displayElement.textContent = allConstraints.length > 0 
            ? `Active Constraints: ${allConstraints.join(' | ')}`
            : 'No constraints active.';
    }

    // Generate passwords
    const passwordIds = ['pass1', 'pass2', 'pass3'];
    passwordIds.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = PasswordGenerator.generate(allConstraints);
        }
    });
}

/**
 * Save password from generator page
 * @param {string} passwordElementId - ID of element containing password
 */
async function savePassword(passwordElementId) {
    const websiteInput = document.getElementById('websiteInput');
    const passwordElement = document.getElementById(passwordElementId);
    
    if (!websiteInput || !passwordElement) {
        alert('Required elements not found on page.');
        return;
    }

    const website = websiteInput.value.trim();
    const password = passwordElement.textContent.trim();
    
    // Get master password securely (should use HTML password input instead of prompt)
    const masterPassword = prompt('Enter your Master Password to save:');
    if (!masterPassword) {
        alert('Master password required to save.');
        return;
    }

    await PasswordManager.save(website, password, masterPassword);
}

/**
 * Display stored passwords in the manager
 */
async function displayStoredPasswords() {
    const masterInput = document.getElementById('masterKeyInput');
    const storedDiv = document.getElementById('storedPasswordsDiv');
    
    if (!masterInput || !storedDiv) {
        console.error('Required elements not found');
        return;
    }

    const masterPassword = masterInput.value.trim();
    if (!masterPassword) {
        alert('Please enter your master password.');
        return;
    }

    try {
        // Show loading state
        storedDiv.innerHTML = '<p style="color:white;">Loading passwords...</p>';

        const credentials = await PasswordManager.retrieve(masterPassword);

        // Clear and populate
        storedDiv.innerHTML = '';

        if (credentials.length === 0) {
            storedDiv.innerHTML = '<p style="color:white;">Your vault is empty.</p>';
            return;
        }

        credentials.forEach((cred) => {
            const itemDiv = document.createElement('div');
            itemDiv.className = 'vault-item';
            itemDiv.style.cssText = 'background:#2a2a2a; padding:15px; margin:10px 0; border-radius:8px; border:1px solid #444;';
            
            const websitePara = document.createElement('p');
            websitePara.innerHTML = `<strong>Service:</strong> ${Validator.sanitizeHTML(cred.website)}`;
            
            const passwordPara = document.createElement('p');
            passwordPara.innerHTML = `<strong>Password:</strong> <span class="hidden-pass">${Validator.sanitizeHTML(cred.password)}</span>`;
            
            const timestampPara = document.createElement('p');
            timestampPara.innerHTML = `<strong>Saved:</strong> ${new Date(cred.timestamp).toLocaleString()}`;
            timestampPara.style.fontSize = '0.9em';
            timestampPara.style.color = '#999';
            
            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = 'Delete';
            deleteBtn.style.cssText = 'background:#ff4b4b; color:white; border:none; padding:8px 15px; border-radius:4px; cursor:pointer; margin-top:10px;';
            deleteBtn.onclick = () => deletePassword(cred.website);
            
            const copyBtn = document.createElement('button');
            copyBtn.textContent = 'Copy Password';
            copyBtn.style.cssText = 'background:#4CAF50; color:white; border:none; padding:8px 15px; border-radius:4px; cursor:pointer; margin-top:10px; margin-left:10px;';
            copyBtn.onclick = () => copyToClipboard(cred.password);
            
            itemDiv.appendChild(websitePara);
            itemDiv.appendChild(passwordPara);
            itemDiv.appendChild(timestampPara);
            itemDiv.appendChild(deleteBtn);
            itemDiv.appendChild(copyBtn);
            
            storedDiv.appendChild(itemDiv);
        });
    } catch (error) {
        storedDiv.innerHTML = `<p style="color:#ff4b4b;">Error: ${error.message}</p>`;
    }
}

/**
 * Delete a password entry
 * @param {string} website - Website to delete
 */
function deletePassword(website) {
    if (!confirm(`Delete password for "${website}"?`)) {
        return;
    }

    const success = PasswordManager.delete(website);
    
    if (success) {
        alert('Password deleted successfully.');
        displayStoredPasswords();
    } else {
        alert('Failed to delete password.');
    }
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 */
async function copyToClipboard(text) {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
            alert('✓ Password copied to clipboard!');
        } else {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            alert('✓ Password copied to clipboard!');
        }
    } catch (error) {
        console.error('Copy failed:', error);
        alert('Failed to copy password. Please copy manually.');
    }
}

/**
 * Save global constraints for current user
 */
function saveGlobalConstraints() {
    const currentUserEmail = StorageModule.getSession(CONFIG.STORAGE_KEYS.SESSION_EMAIL);
    
    if (!currentUserEmail) {
        alert('Please login to save your custom rules.');
        return;
    }

    const inputs = document.getElementsByClassName('constraint-input');
    const globals = [];

    for (let i = 0; i < inputs.length; i++) {
        const val = inputs[i].value.trim();
        if (val) {
            globals.push(Validator.sanitizeHTML(val));
        }
    }

    const userSpecificKey = `globalConstraints_${currentUserEmail}`;
    const success = StorageModule.setItem(userSpecificKey, globals);
    
    if (success) {
        alert('✓ Your personal rules have been saved!');
        window.location.href = CONFIG.PAGES.HOME;
    } else {
        alert('Failed to save rules.');
    }
}

/**
 * Create constraint input fields dynamically
 */
function createConstraintInputs() {
    const numInput = document.getElementById('numConstraints');
    const inputDiv = document.getElementById('constraintInputs');
    
    if (!numInput || !inputDiv) return;

    const num = parseInt(numInput.value);
    
    // Validate
    const validation = Validator.validateConstraintCount(num);
    if (!validation.valid) {
        alert(validation.error);
        inputDiv.innerHTML = '';
        return;
    }

    inputDiv.innerHTML = '';

    for (let i = 0; i < num; i++) {
        const inputField = document.createElement('input');
        inputField.type = 'text';
        inputField.className = 'constraint-input';
        inputField.placeholder = `Constraint ${i + 1} (e.g., 'Google')`;
        inputField.maxLength = 20;
        inputField.style.cssText = 'margin-bottom:10px; padding:8px; width:100%; border-radius:4px; border:1px solid #ccc;';
        
        inputDiv.appendChild(inputField);
        inputDiv.appendChild(document.createElement('br'));
    }
}

/**
 * Save session constraints and redirect to generator
 */
function saveConstraints() {
    const constraintInputs = document.getElementsByClassName('constraint-input');
    const constraints = [];

    for (let i = 0; i < constraintInputs.length; i++) {
        const value = constraintInputs[i].value.trim();
        if (value.length > 0) {
            constraints.push(Validator.sanitizeHTML(value));
        }
    }

    StorageModule.setItem(CONFIG.STORAGE_KEYS.PASSWORD_CONSTRAINTS, constraints);
    window.location.href = CONFIG.PAGES.GENERATOR;
}

/**
 * Handle user logout
 */
function handleLogout() {
    StorageModule.clearSession();
    alert('✓ You have been logged out successfully.');
    window.location.href = CONFIG.PAGES.INDEX;
}

/**
 * Initialize master password on login (called from login page)
 * @param {string} email - User email
 * @param {string} masterPassword - Master password
 */
async function initializeSession(email, masterPassword) {
    try {
        // Validate master password
        const validation = Validator.validateMasterPassword(masterPassword);
        if (!validation.valid) {
            alert(validation.error);
            return false;
        }

        // Hash the master password
        const masterKeyHash = await CryptoModule.hashSHA256(masterPassword);
        
        // Store in session
        StorageModule.setSession(CONFIG.STORAGE_KEYS.SESSION_EMAIL, email);
        StorageModule.setSession(CONFIG.STORAGE_KEYS.SESSION_KEY_HASH, masterKeyHash);
        
        return true;
    } catch (error) {
        console.error('Session initialization error:', error);
        return false;
    }
}

// --- 8. UTILITY FUNCTIONS ---

/**
 * Check if Web Crypto API is available
 * @returns {boolean}
 */
function isCryptoAvailable() {
    return window.crypto && window.crypto.subtle;
}

/**
 * Initialize application
 */
function initializeApp() {
    if (!isCryptoAvailable()) {
        console.warn('Web Crypto API not available - security features limited');
        alert('Warning: Your browser does not support modern encryption. Please use a modern browser for better security.');
    }
