// Toggle between Sign In and Sign Up
const toggleFormButton = document.getElementById('toggleForm');
const firstNameGroup = document.getElementById('nameGroup');
const lastNameGroup = document.getElementById('lastNameGroup');
const confirmPasswordGroup = document.getElementById('confirmPasswordGroup');
const authTitle = document.getElementById('authTitle');
const authButton = document.getElementById('authButton');
let isSignIn = true;

toggleFormButton.addEventListener('click', () => {
  isSignIn = !isSignIn;
  firstNameGroup.style.display = isSignIn ? 'none' : 'block';
  lastNameGroup.style.display = isSignIn ? 'none' : 'block';
  confirmPasswordGroup.style.display = isSignIn ? 'none' : 'block';
  authTitle.textContent = isSignIn ? 'Welcome Back!' : 'Create an Account';
  authButton.textContent = isSignIn ? 'Sign In' : 'Sign Up';
  toggleFormButton.textContent = isSignIn
    ? "Don't have an account? Sign Up"
    : 'Already have an account? Sign In';
});
