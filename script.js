// --- 1. CORE UTILITIES (Must be at the top) ---

// Helper for Encryption/Decryption
const simpleCrypt = (text, key) => {
    return text.split('').map((char, i) => 
        String.fromCharCode(char.charCodeAt(0) ^ key.charCodeAt(i % key.length))
    ).join('');
};

// Helper for Verification Hashing
const getHash = (str) => {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash |= 0; 
    }
    return hash.toString();
};

// --- 2. GENERATOR LOGIC ---

const PASSWORD_LENGTH = 16;
const CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

function generatePassword(constraints) {
    let password = "";
    let baseLength = constraints.reduce((sum, c) => sum + c.length, 0);
    
    if (baseLength >= PASSWORD_LENGTH) {
        alert("Constraints too long!");
        window.location.href = "Constraints.html";
        return "";
    }

    let remainingLength = PASSWORD_LENGTH - baseLength;
    let pool = "";
    for(let i=0; i<remainingLength; i++) {
        pool += CHARSET[Math.floor(Math.random() * CHARSET.length)];
    }

    // Combine constraints and random chars
    let result = [...constraints, ...pool.split('')];
    // Shuffle
    for (let i = result.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [result[i], result[j]] = [result[j], result[i]];
    }
    return result.join('');
}

function displayGeneratedPasswords() {
    const currentUserEmail = sessionStorage.getItem('currentUserEmail');
    
    // 1. Get the Global Rules for THIS specific user
    let globalRules = [];
    if (currentUserEmail) {
        const userSpecificKey = `globalConstraints_${currentUserEmail}`;
        const globalJson = localStorage.getItem(userSpecificKey);
        globalRules = globalJson ? JSON.parse(globalJson) : [];
    }

    // 2. Get the session rules (temporary)
    const sessionJson = localStorage.getItem("passwordConstraints");
    const sessionRules = sessionJson ? JSON.parse(sessionJson) : [];

    // Combine them
    const allConstraints = [...new Set([...globalRules, ...sessionRules])];

    const displayElement = document.getElementById("constraintsUsed");
    if (displayElement) {
        displayElement.innerHTML = allConstraints.length > 0 
            ? "Active Constraints: **" + allConstraints.join(" | ") + "**"
            : "No constraints active.";
    }

    document.getElementById("pass1").innerHTML = generatePassword(allConstraints);
    document.getElementById("pass2").innerHTML = generatePassword(allConstraints);
    document.getElementById("pass3").innerHTML = generatePassword(allConstraints);
}

// --- 3. PASSWORD MANAGER LOGIC ---

function savePassword(passwordElementId) {
    // 1. Get Session Data
    const activeMasterKey = sessionStorage.getItem('currentMasterKey');
    const currentUserEmail = sessionStorage.getItem('currentUserEmail');

    if (!activeMasterKey || !currentUserEmail) {
        alert("Please login first to save passwords.");
        window.location.href = "PG-2.html";
        return;
    }

    const websiteInput = document.getElementById("websiteInput");
    const website = websiteInput ? websiteInput.value.trim() : "";
    const password = document.getElementById(passwordElementId).textContent.trim();
    
    if (!website || password === 'Click "Generate"') {
        alert("Please enter a website name and generate a password.");
        return;
    }

    // 2. Verification
    const masterVerify = prompt("Confirm Master Password to save:");
    if (masterVerify !== activeMasterKey) {
        alert("Incorrect Master Password. Unauthorized.");
        return;
    }

    // 3. Update/Save Logic
    let allCredentials = JSON.parse(localStorage.getItem("passwordManager") || "[]");
    
    // Filter out existing entry for this specific user and website
    allCredentials = allCredentials.filter(cred => 
        !(cred.website.toLowerCase() === website.toLowerCase() && cred.owner === currentUserEmail)
    );

    const encryptedPassword = btoa(simpleCrypt(password, activeMasterKey));
    
    allCredentials.push({
        website: website,
        password: encryptedPassword,
        timestamp: new Date().toLocaleString(),
        owner: currentUserEmail // Crucial for user isolation
    });

    localStorage.setItem("passwordManager", JSON.stringify(allCredentials));
    
    alert("Success! Password saved to your vault.");
    window.location.href = "password_manager.html"; // Match your filename exactly
}

function displayStoredPasswords() {
    const masterInput = document.getElementById("masterKeyInput");
    const activeMasterKey = sessionStorage.getItem('currentMasterKey');
    const currentUserEmail = sessionStorage.getItem('currentUserEmail');
    const storedDiv = document.getElementById("storedPasswordsDiv");

    if (!masterInput || masterInput.value !== activeMasterKey) {
        alert("Invalid Master Key.");
        return;
    }

    const allCredentials = JSON.parse(localStorage.getItem("passwordManager") || "[]");
    const userCredentials = allCredentials.filter(cred => cred.owner === currentUserEmail);

    storedDiv.innerHTML = "";
    if (userCredentials.length === 0) {
        storedDiv.innerHTML = "<p style='color:white;'>Your vault is empty.</p>";
        return;
    }

    userCredentials.forEach((cred) => {
        const decryptedPass = simpleCrypt(atob(cred.password), activeMasterKey);
        const itemDiv = document.createElement("div");
        itemDiv.className = "vault-item";
        itemDiv.innerHTML = `
            <p><strong>Service:</strong> ${cred.website}</p>
            <p><strong>Password:</strong> <span class="hidden-pass">${decryptedPass}</span></p>
            <button onclick="deletePassword('${cred.website}')" style="background:#ff4b4b; color:white; border:none; padding:5px; border-radius:4px; cursor:pointer;">Delete</button>
        `;
        storedDiv.appendChild(itemDiv);
    });
}

function deletePassword(websiteToDelete) {
    if (!confirm(`Delete ${websiteToDelete}?`)) return;
    const currentUserEmail = sessionStorage.getItem('currentUserEmail');
    let all = JSON.parse(localStorage.getItem("passwordManager") || "[]");
    all = all.filter(c => !(c.website === websiteToDelete && c.owner === currentUserEmail));
    localStorage.setItem("passwordManager", JSON.stringify(all));
    displayStoredPasswords();
}

function saveGlobalConstraints() {
    const currentUserEmail = sessionStorage.getItem('currentUserEmail');
    
    if (!currentUserEmail) {
        alert("Please login to save your custom rules.");
        return;
    }

    const inputs = document.getElementsByClassName("constraint-input");
    let globals = [];

    for (let i = 0; i < inputs.length; i++) {
        const val = inputs[i].value.trim();
        if (val) globals.push(val);
    }

    // Save using a unique key per user
    const userSpecificKey = `globalConstraints_${currentUserEmail}`;
    localStorage.setItem(userSpecificKey, JSON.stringify(globals));
    
    alert("Your personal rules have been saved!");
    window.location.href = "Home_Page.html";
}

// --- Functions for constraints.html ---

function createConstraintInputs() {
    const numInput = document.getElementById("numConstraints");
    // Ensure the element exists before trying to read it
    if (!numInput) return;

    const num = parseInt(numInput.value);
    const inputDiv = document.getElementById("constraintInputs");

    // Basic validation
    if (isNaN(num) || num < 1 || num > 5) {
        alert("Please enter a valid number between 1 and 5.");
        inputDiv.innerHTML = "";
        return;
    }

    inputDiv.innerHTML = ""; // Clear any previous inputs

    for (let i = 0; i < num; i++) {
        const inputField = document.createElement("input");
        inputField.type = "text";
        inputField.className = "constraint-input"; // Class used by saveConstraints
        inputField.placeholder = "Constraint " + (i + 1) + " (e.g., 'Google')";
        inputField.style.marginBottom = "10px"; // Visual spacing
        
        inputDiv.appendChild(inputField);
        inputDiv.appendChild(document.createElement("br"));
    }
}

function saveConstraints() {
    const constraintInputs = document.getElementsByClassName("constraint-input");
    let constraints = [];

    // Collect all non-empty values
    for (let i = 0; i < constraintInputs.length; i++) {
        const value = constraintInputs[i].value.trim();
        if (value.length > 0) {
            constraints.push(value);
        }
    }

    // Save for the current session
    localStorage.setItem("passwordConstraints", JSON.stringify(constraints));

    // Navigate to the generator page
    window.location.href = "password_generator.html";
}

function handleLogout() {
    // 1. Clear the session-specific data
    // This removes the Master Key and the current user's email from memory
    sessionStorage.removeItem('currentMasterKey');
    sessionStorage.setItem('currentUserEmail', '');
    sessionStorage.clear(); // Optional: clears all session data for safety

    // 2. Alert the user and redirect to the landing page
    alert("You have been logged out successfully.");
    window.location.href = "PG-1.html";
}