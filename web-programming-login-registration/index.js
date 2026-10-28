
const express = require("express");
const crypto = require("crypto");
const mysql = require("mysql2");
const path = require("path");

const app = express();

// Allows Express to read HTML form submissions
app.use(express.urlencoded({ extended: true }));

// Allows the website to load CSS from the public folder
app.use(express.static(path.join(__dirname, "public")));

// Database connection from the previous assignment
const conn = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "web_programming",
    port: 3306
});

// Connects Node.js to the MySQL database
conn.connect(function(err) {
    if (err) {
        console.log("Couldnt connect to MySQL", err);
    } else {
        console.log("Database connection established");
    }
});

// Creates a password hash using a random salt
function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(
        password, salt, 100000, 64, "sha512"
    ).toString("hex");
}

// Displays the registration page
app.get("/register.html", function(req, res) {
    res.sendFile(path.join(__dirname, "register.html"));
});

// Displays the login page
app.get("/login.html", function(req, res) {
    res.sendFile(path.join(__dirname, "login.html"));
});

// Handles registration form submissions
app.post("/register", function(req, res) {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    // Checks that all registration fields are filled in
    if (!username || !email || !password) {
        return res.send("Please fill out all fields.");
    }

    // Hashes the password before saving it
    const salt = crypto.randomBytes(16).toString("hex");
    const hashedPassword = hashPassword(password, salt);
    const storedPassword = salt + ":" + hashedPassword;

    // Inserts the registered user into the database
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

            // Displays a successful registration message
            res.send(
                '<p>You have successfully registered!</p>' +
                '<a href="/login.html">Go to Login</a>'
            );
        }
    );
});

// Handles login form submissions
app.post("/login", function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    // Searches for the registered username
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

        // Checks the entered password against the saved hash
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

        // Displays the appropriate login message
        if (valid) {
            res.send(
                "<p>You have logged in successfully!</p>"
            );
        } else {
            res.send(
                "<p>The login credentials were incorrect.</p>" +
                '<a href="/login.html">Back to Login</a>'
            );
        }
    });
});

// Starts the Node.js server
app.listen(3000, function() {
    console.log("Server running on port 3000");
});
