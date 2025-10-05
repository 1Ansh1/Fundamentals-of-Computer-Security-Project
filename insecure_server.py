from flask import Flask, request, render_template_string

# Create a Flask web server instance
app = Flask(__name__)

# This is the HTML code for our simple login page
LOGIN_FORM_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insecure Login</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: #ffffff;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        h2 {
            margin-top: 0;
            margin-bottom: 10px;
            color: #333;
        }
        .subtitle {
            margin-bottom: 30px;
            color: #666;
        }
        .input-group {
            margin-bottom: 20px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 6px;
            box-sizing: border-box; /* Important for padding and width */
        }
        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 6px;
            background-color: #007bff;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        button:hover {
            background-color: #0056b3;
        }
        .warning {
            margin-top: 25px;
            color: #dc3545;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <form action="/login" method="post">
            <h2>Welcome Back</h2>
            <p class="subtitle">Please enter your credentials to log in.</p>
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
            <p class="warning">Warning: This form connection is not secure.</p>
        </form>
    </div>
</body>
</html>
"""

# This function runs when someone visits the main page ("/")
@app.route("/")
def home():
    return render_template_string(LOGIN_FORM_HTML)

# This function runs when the login form is submitted
@app.route("/login", methods=["POST"])
def login():
    # Get the username and password from the submitted form data
    username = request.form.get("username")
    password = request.form.get("password")
    return f"<h1>Login Attempted!</h1><p>Username: {username}</p><p>Password: {password}</p>"

# Start the server when the script is run
if __name__ == "__main__":
    # The server will be accessible at http://127.0.0.1:5000
    app.run(host="127.0.0.1", port=5000)