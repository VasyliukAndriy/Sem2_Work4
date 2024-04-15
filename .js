const bcrypt = require('bcrypt');
const prompt = require('prompt-sync')();

async function hashAndCheckPassword(password) {
    const isValid = validatePassword(password);
    if (isValid) {
        try {
            const hash = await bcrypt.hash(password, 10);
            console.log("Hashed Password:", hash);
            await checkPassword(password, hash);
        } catch (error) {
            console.error("Error occurred during hashing:", error);
        }
    } else {
        console.log("Invalid Password");
    }
}

async function checkPassword(password, hash) {
    try {
        const isMatch = await bcrypt.compare(password, hash);
        console.log("Password Matches:", isMatch);
    } catch (error) {
        console.error("Error occurred during password comparison:", error);
    }
}

function validatePassword(password) {
    const hasLowerCase = /[a-z]/.test(password);
    const hasUpperCase = /[A-Z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    const isLengthValid = password.length >= 8;
    return hasLowerCase && hasUpperCase && hasDigit && hasSpecialChar && isLengthValid;
}

const password = prompt("Enter your password: ");
hashAndCheckPassword(password);
