from flask import Flask, request, render_template_string

# Create a Flask web server instance
app = Flask(__name__)

# This is the HTML code for our simple login page
LOGIN_FORM_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Insecure Login Page</title>
</head>
<body>
    <h2>Enter Your Credentials (Insecurely!)</h2>
    <form action="/login" method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
    <p style="color:red;">Warning: This form is not secure. Do not use real passwords.</p>
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