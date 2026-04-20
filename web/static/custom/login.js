/**
 * paraKang Login Page — Form Handling & Interactions
 * Manages form validation, submission, and UX enhancements
 */

class LoginForm {
  constructor() {
    this.form = document.getElementById('login-form');
    this.submitBtn = document.getElementById('login-btn');
    this.usernameField = document.getElementById('username');
    this.passwordField = document.getElementById('password');
    this.rememberMeCheckbox = document.getElementById('remember-me');
    this.passwordToggle = null;

    if (!this.form) {
      console.warn('Login form not found');
      return;
    }

    this.init();
  }

  init() {
    this.setupEventListeners();
    this.setupPasswordToggle();
    this.restoreRememberMe();
    this.focusFirstEmptyField();
  }

  setupEventListeners() {
    // Form submission
    this.form.addEventListener('submit', (e) => this.handleSubmit(e));

    // Field validation
    if (this.usernameField) {
      this.usernameField.addEventListener('input', () => this.validateUsername());
      this.usernameField.addEventListener('blur', () => this.validateUsername());
    }

    if (this.passwordField) {
      this.passwordField.addEventListener('input', () => this.validatePassword());
      this.passwordField.addEventListener('blur', () => this.validatePassword());
    }

    // Remember me
    if (this.rememberMeCheckbox) {
      this.rememberMeCheckbox.addEventListener('change', () => this.handleRememberMe());
    }

    // Enter key handling
    this.form.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && e.target !== this.submitBtn) {
        e.preventDefault();
        this.handleSubmit(e);
      }
    });
  }

  setupPasswordToggle() {
    const toggleBtn = this.form.querySelector('.field-toggle-pw');
    if (!toggleBtn || !this.passwordField) {
      return;
    }

    this.passwordToggle = toggleBtn;
    this.passwordToggle.addEventListener('click', (e) => {
      e.preventDefault();
      this.togglePasswordVisibility();
    });

    // Update icon based on initial state
    this.updatePasswordToggleIcon();
  }

  togglePasswordVisibility() {
    const isPassword = this.passwordField.type === 'password';
    this.passwordField.type = isPassword ? 'text' : 'password';
    this.updatePasswordToggleIcon();
  }

  updatePasswordToggleIcon() {
    const eyeOpen = this.passwordToggle.querySelector('.eye-open');
    const eyeClosed = this.passwordToggle.querySelector('.eye-closed');

    if (this.passwordField.type === 'password') {
      eyeClosed?.style.setProperty('display', 'block');
      eyeOpen?.style.setProperty('display', 'none');
    } else {
      eyeOpen?.style.setProperty('display', 'block');
      eyeClosed?.style.setProperty('display', 'none');
    }
  }

  restoreRememberMe() {
    if (!this.rememberMeCheckbox) return;

    const savedUsername = localStorage.getItem('parakang_login_username');
    if (savedUsername) {
      this.usernameField.value = savedUsername;
      this.rememberMeCheckbox.checked = true;
    }
  }

  handleRememberMe() {
    if (this.rememberMeCheckbox.checked) {
      localStorage.setItem('parakang_login_username', this.usernameField.value);
    } else {
      localStorage.removeItem('parakang_login_username');
    }
  }

  validateUsername() {
    if (!this.usernameField) return true;

    const username = this.usernameField.value.trim();
    const isValid = username.length >= 1;

    this.updateFieldState(this.usernameField, isValid);
    return isValid;
  }

  validatePassword() {
    if (!this.passwordField) return true;

    const password = this.passwordField.value;
    const isValid = password.length >= 1;

    this.updateFieldState(this.passwordField, isValid);
    return true;
  }

  updateFieldState(field, isValid) {
    const fieldWrapper = field.closest('.form-field');
    if (!fieldWrapper) return;

    if (field.value.length === 0) {
      fieldWrapper.classList.remove('field-error');
    } else if (!isValid) {
      fieldWrapper.classList.add('field-error');
    } else {
      fieldWrapper.classList.remove('field-error');
    }
  }

  focusFirstEmptyField() {
    if (this.usernameField && this.usernameField.value === '') {
      this.usernameField.focus();
    } else if (this.passwordField) {
      this.passwordField.focus();
    }
  }

  handleSubmit(e) {
    e.preventDefault();

    // Validate
    const usernameValid = this.validateUsername();
    const passwordValid = this.validatePassword();

    if (!usernameValid || !passwordValid) {
      this.showError('Please fill in all fields');
      return;
    }

    // Save remember me preference
    if (this.rememberMeCheckbox?.checked) {
      this.handleRememberMe();
    }

    // Submit form
    this.submitForm();
  }

  submitForm() {
    if (!this.form || !this.submitBtn) return;

    // Disable button and show loading state
    this.submitBtn.disabled = true;
    this.submitBtn.classList.add('is-loading');

    // Get form data
    const formData = new FormData(this.form);
    const actionUrl = this.form.action || '/auth/login/';

    // Submit via fetch to handle response better
    fetch(actionUrl, {
      method: 'POST',
      body: formData,
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
      },
      credentials: 'same-origin',
      redirect: 'follow',
    })
      .then((response) => {
        // Check if response is successful (2xx)
        if (response.ok) {
          this.submitBtn.classList.remove('is-loading');
          this.submitBtn.classList.add('is-success');

          // Announce to screen readers
          this.announceToScreenReader('Login successful, redirecting...');

          // Get next URL from form or default to root
          const nextUrl = formData.get('next') || '/';

          // Redirect after a brief delay
          setTimeout(() => {
            window.location.href = nextUrl;
          }, 600);
        } else if (response.status === 401) {
          // Authentication failed
          throw new Error('Invalid credentials');
        } else {
          throw new Error(`Login failed with status ${response.status}`);
        }
      })
      .catch((error) => {
        this.submitBtn.disabled = false;
        this.submitBtn.classList.remove('is-loading');
        this.showError(error.message || 'Login failed. Please try again.');
      });
  }

  showError(message) {
    // Find or create error alert
    let errorAlert = this.form.querySelector('.login-alert--error');

    if (!errorAlert) {
      errorAlert = document.createElement('div');
      errorAlert.className = 'login-alert login-alert--error';
      errorAlert.role = 'alert';
      errorAlert.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="15" y1="9" x2="9" y2="15"></line>
          <line x1="9" y1="9" x2="15" y2="15"></line>
        </svg>
        <div>
          <strong>Login Error</strong>
          <span></span>
        </div>
      `;
      this.form.insertBefore(errorAlert, this.form.firstChild);
    }

    // Update message
    const messageSpan = errorAlert.querySelector('span');
    if (messageSpan) {
      messageSpan.textContent = message;
    }

    // Show alert with animation
    errorAlert.style.display = 'flex';
    errorAlert.style.animation = 'slideDown 0.4s ease-out';

    // Announce to screen readers
    this.announceToScreenReader(`Error: ${message}`);

    // Auto-hide after 5 seconds
    setTimeout(() => {
      errorAlert.style.opacity = '0';
      errorAlert.style.transition = 'opacity 0.3s ease-out';
      setTimeout(() => {
        errorAlert.style.display = 'none';
        errorAlert.style.opacity = '1';
      }, 300);
    }, 5000);
  }

  announceToScreenReader(message) {
    const announcer = document.getElementById('sr-announce');
    if (announcer) {
      announcer.textContent = message;
    }
  }
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.loginForm = new LoginForm();
  });
} else {
  window.loginForm = new LoginForm();
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  // Ctrl/Cmd + Enter to submit
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    const form = document.getElementById('login-form');
    if (form) {
      form.dispatchEvent(new Event('submit'));
    }
  }
});
