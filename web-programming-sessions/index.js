
const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql2");
const path = require("path");
const session = require("express-session");

const app = express();

// Reads information submitted through HTML forms
app.use(express.urlencoded({ extended: true }));

// Loads CSS and other public website files
app.use(express.static(path.join(__dirname, "public")));

// Creates session storage for logged-in users
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax"
    }
}));

// Connects to the existing MySQL database
const conn = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "web_programming",
    port: 3306
});

conn.connect(function(err) {
    if (err) {
        console.log("Database connection failed:", err);
    } else {
        console.log("Database connection established");
    }
});

// Creates a secure password hash using a salt
function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(
        password, salt, 100000, 64, "sha512"
    ).toString("hex");
}

// Prevents usernames from being interpreted as HTML
function escapeHTML(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// Creates the profile dropdown shown on every page
function profileMenu(req) {
    const loggedIn = Boolean(req.session.username);
    const username = loggedIn
        ? escapeHTML(req.session.username)
        : "Guest";

    const links = loggedIn
        ? `
            <a href="/profile">View Profile</a>
            <a href="/logout">Sign Out</a>
          `
        : `
            <a href="/login.html">Login</a>
            <a href="/register.html">Register</a>
          `;

    return `
        <div class="profile-menu">
            <span class="profile-username">${username}</span>

            <details class="profile-dropdown">
                <summary aria-label="Open account menu">
                    <span class="profile-avatar">👤</span>
                </summary>

                <div class="profile-dropdown-content">
                    ${links}
                </div>
            </details>
        </div>
    `;
}

// Creates a complete page with the account menu
function renderPage(req, title, content) {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1.0">
            <title>${title} | LEGO Star Wars Hub</title>
            <link rel="stylesheet" href="/styles.css">
        </head>
        <body>
            ${profileMenu(req)}

            <main>
                <h1>LEGO Star Wars Hub</h1>
                ${content}
            </main>
        </body>
        </html>
    `;
}

// Displays the registration form with the profile menu
app.get("/register.html", function(req, res) {
    res.send(renderPage(req, "Register", `
        <h2>Create an Account</h2>
        <p>Register to become a member of our website!</p>

        <form action="/register" method="POST">
            <label for="username">Username:</label>
            <input type="text" id="username"
                   name="username" required>

            <label for="email">Email:</label>
            <input type="email" id="email"
                   name="email" required>

            <label for="password">Password:</label>
            <input type="password" id="password"
                   name="password" minlength="8" required>

            <button type="submit">Register</button>
        </form>

        <p>Already have an account?
            <a href="/login.html">Login here</a>
        </p>
    `));
});

// Displays the login form with the profile menu
app.get("/login.html", function(req, res) {
    res.send(renderPage(req, "Login", `
        <h2>Login to Your Account</h2>
        <p>Welcome back! Enter your username and password.</p>

        <form action="/login" method="POST">
            <label for="username">Username:</label>
            <input type="text" id="username"
                   name="username" required>

            <label for="password">Password:</label>
            <input type="password" id="password"
                   name="password" required>

            <button type="submit">Login</button>
        </form>

        <p>Don't have an account?
            <a href="/register.html">Register here</a>
        </p>
    `));
});

// Registers a new user in the MySQL database
app.post("/register", function(req, res) {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    // Checks for missing registration fields
    if (!username || !email || !password) {
        return res.send(renderPage(req, "Register", `
            <h2>Please fill out all fields.</h2>
            <a href="/register.html">Try Again</a>
        `));
    }

    // Hashes the password before saving it
    const salt = crypto.randomBytes(16).toString("hex");
    const hashedPassword = hashPassword(password, salt);
    const storedPassword = salt + ":" + hashedPassword;

    const sql = `
        INSERT INTO users (username, email, password_hash)
        VALUES (?, ?, ?)
    `;

    conn.query(sql, [username, email, storedPassword],
        function(err) {
            if (err) {
                console.log("Registration error:", err);
                return res.status(500).send(
                    "Registration failed. Please try again."
                );
            }

            res.send(renderPage(req, "Registered", `
                <h2>You have successfully registered!</h2>
                <a href="/login.html">Go to Login</a>
            `));
        }
    );
});

// Checks the username and password during login
app.post("/login", function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    const sql = `
        SELECT password_hash FROM users
        WHERE username = ? AND password_hash IS NOT NULL
    `;

    conn.query(sql, [username], function(err, results) {
        if (err) {
            console.log("Login error:", err);
            return res.status(500).send("Login error.");
        }

        let valid = false;

        // Compares the entered password with saved hashes
        for (const user of results) {
            const stored = user.password_hash.split(":");

            if (stored.length !== 2) continue;

            const [salt, savedHash] = stored;
            const enteredHash = hashPassword(password || "", salt);

            if (enteredHash === savedHash) {
                valid = true;
                break;
            }
        }

        // Rejects incorrect login credentials
        if (!valid) {
            return res.send(renderPage(req, "Login Failed", `
                <h2>The login credentials were incorrect.</h2>
                <a href="/login.html">Back to Login</a>
            `));
        }

        // Creates a new session after successful login
        req.session.regenerate(function(err) {
            if (err) {
                return res.status(500).send("Session error.");
            }

            // Stores the username in the session
            req.session.username = username;

            req.session.save(function(err) {
                if (err) {
                    return res.status(500).send("Session error.");
                }

                res.send(renderPage(req, "Welcome", `
                    <h2>You have logged in successfully!</h2>
                    <p>Welcome back, ${escapeHTML(username)}!</p>
                    <a href="/profile">View Your Profile</a>
                `));
            });
        });
    });
});

// Displays the profile using the saved session username
app.get("/profile", function(req, res) {
    // Prevents guests from viewing a private profile
    if (!req.session.username) {
        return res.redirect("/login.html");
    }

    const username = escapeHTML(req.session.username);

    res.send(renderPage(req, "Profile", `
        <h2>Your Profile</h2>

        <div class="profile-card">
            <div class="large-avatar">👤</div>
            <h2>${username}</h2>
            <p>You are currently logged in.</p>
        </div>

        <p><a href="/logout">Sign Out</a></p>
    `));
});

// Destroys the session when the user signs out
app.get("/logout", function(req, res) {
    req.session.destroy(function(err) {
        if (err) {
            return res.status(500).send("Logout failed.");
        }

        // Removes the session cookie from the browser
        res.clearCookie("connect.sid");

        // The menu now shows Guest, Login, and Register
        res.redirect("/login.html");
    });
});

// Redirects the homepage to the login page
app.get("/", function(req, res) {
    res.redirect("/login.html");
});

// Starts the Node.js server
app.listen(3000, function() {
    console.log("Server running on port 3000");
});
