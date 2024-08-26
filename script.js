document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');

    if (registerForm) {
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            const formData = new FormData(registerForm);
            const username = formData.get('username');
            const full_name = formData.get('full_name');
            const email = formData.get('email');
            const password = formData.get('password');

            try {
                const response = await fetch('/plp/users/registration', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, email, password, full_name })
                });

                if (response.ok) {
                    alert('Registration successful');
                    // Redirect or clear the form as needed
                } else {
                    const data = await response.json();
                    const errorMessages = data.errors.map(error => error.msg).join(', ');
                    alert('Registration failed: ' + errorMessages);
                }
            } catch (error) {
                console.error('Error occurred:', error);
                alert('An unexpected error occurred. Please try again later.');
            }
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            const formData = new FormData(loginForm);
            const username = formData.get('username');
            const password = formData.get('password');

            try {
                const response = await fetch('/plp/users/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });

                if (response.ok) {
                    alert('Login successful');
                    // Redirect or update UI as needed
                } else {
                    const data = await response.json();
                    alert('Login failed: ' + data.error);
                }
            } catch (error) {
                console.error('Error occurred:', error);
                alert('An unexpected error occurred. Please try again later.');
            }
        });
    }
});

