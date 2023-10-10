// Get references to the form and input fields
const signUpForm = document.getElementById('signup-form');
const usernameInput = document.getElementById('username');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const confirmPasswordInput = document.getElementById('confirm-password');
const signUpButton = document.querySelector('.signup-button');

// Function to enable/disable the "Sign Up" button based on input validation
function validateForm() {
    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    // Check if all fields are filled and passwords match
    if (username !== '' && email !== '' && password !== '' && confirmPassword === password) {
        signUpButton.removeAttribute('disabled');
    } else {
        signUpButton.setAttribute('disabled', true);
    }
}

// Add event listeners to input fields for real-time validation
usernameInput.addEventListener('input', validateForm);
emailInput.addEventListener('input', validateForm);
passwordInput.addEventListener('input', validateForm);
confirmPasswordInput.addEventListener('input', validateForm);

// Call the validateForm function to initially disable the button
validateForm();
