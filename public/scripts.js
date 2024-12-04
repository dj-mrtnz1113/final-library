// For Admin Registration
const adminForm = document.getElementById('admin-register-form');
if (adminForm) {
    adminForm.addEventListener('submit', function(event) {
        event.preventDefault();

        // Get the values of the form fields
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        const data = {
            username: username,
            password: password
        };

        // Make the API request using fetch
        fetch('http://localhost:8000/admin/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        })
        .then(response => response.json())
        .then(data => {
            const responseMessage = document.getElementById('response-message');
            if (data.status === 'success') {
                responseMessage.textContent = 'Registration successful!';
                responseMessage.style.color = 'green';
                // After successful registration, try logging the user in automatically
                loginUser(username, password);
            } else {
                responseMessage.textContent = `Error: ${data.data.title}`;
                responseMessage.style.color = 'red';
            }
        })
        .catch(error => {
            const responseMessage = document.getElementById('response-message');
            responseMessage.textContent = 'An error occurred. Please try again.';
            responseMessage.style.color = 'red';
        });
    });
}

// For User Registration (if the user registration form exists)
const userForm = document.getElementById('user-register-form');
if (userForm) {
    userForm.addEventListener('submit', function(event) {
        event.preventDefault();

        // Get the values of the form fields
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        const data = {
            username: username,
            password: password
        };

        // Make the API request using fetch
        fetch('http://localhost:8000/user/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        })
        .then(response => response.json())
        .then(data => {
            const responseMessage = document.getElementById('response-message');
            if (data.status === 'success') {
                responseMessage.textContent = 'Registration successful!';
                responseMessage.style.color = 'green';
                // After successful registration, try logging the user in automatically
                loginUser(username, password);
            } else {
                responseMessage.textContent = `Error: ${data.data.title}`;
                responseMessage.style.color = 'red';
            }
        })
        .catch(error => {
            const responseMessage = document.getElementById('response-message');
            responseMessage.textContent = 'An error occurred. Please try again.';
            responseMessage.style.color = 'red';
        });
    });
}

// For the login form
const loginForm = document.getElementById('login-form'); // Adjust to your form ID
if (loginForm) {
    loginForm.addEventListener('submit', function (event) {
        event.preventDefault(); // Prevent default form submission

        // Get the values of the form fields
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        // Call loginUser function
        loginUser(username, password);
    });
}

// Function to handle user login after registration
function loginUser(username, password) {
    const data = {
        username: username,
        password: password
    };

    // Make the API request using fetch to authenticate the user
    fetch('http://localhost:8000/user/authenticate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    })
    .then(response => response.json())
    .then(data => {
        const responseMessage = document.getElementById('response-message');
        if (data.status === 'success') {
            responseMessage.textContent = 'Login successful!';
            responseMessage.style.color = 'green';
            
            // Store the JWT token in a cookie for 1 day
            setCookie('auth_token', data.token, 1);

            // Check user role and redirect accordingly
            if (data.role === 1) {
                // If the user is an admin (role 1)
                window.location.href = '/public/admin_index.html'; // Redirect to admin panel
            } else if (data.role === 2) {
                // If the user is a regular user (role 2)
                window.location.href = '/public/dashboard.html'; // Redirect to user dashboard
            } else {
                // If the role is not recognized
                responseMessage.textContent = 'Invalid role.';
                responseMessage.style.color = 'red';
            }
        } else {
            // Handle authentication failure (e.g., incorrect username/password)
            responseMessage.textContent = `Error: ${data.data.title}`;
            responseMessage.style.color = 'red';
        }
    })
    .catch(error => {
        // Handle any network errors or unexpected issues
        const responseMessage = document.getElementById('response-message');
        responseMessage.textContent = 'An error occurred. Please try again.';
        responseMessage.style.color = 'red';
    });
}

// Function to set a cookie
function setCookie(name, value, days) {
    const d = new Date();
    d.setTime(d.getTime() + (days * 24 * 60 * 60 * 1000));  // Expiry time
    const expires = "expires=" + d.toUTCString();
    document.cookie = name + "=" + value + ";" + expires + ";path=/";
}