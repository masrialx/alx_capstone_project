const passwordInput = document.getElementById('password');
const confirmPasswordInput = document.getElementById('confirm-password');
const signUpButton = document.querySelector('.signup-button');

// Function to enable or disable the "Sign Up" button based on password match
function checkPasswordMatch() {
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (password === confirmPassword) {
        signUpButton.disabled = false;
    } else {
        signUpButton.disabled = true;
    }
}

// Add an input event listener to both password fields
passwordInput.addEventListener('input', checkPasswordMatch);
confirmPasswordInput.addEventListener('input', checkPasswordMatch);
