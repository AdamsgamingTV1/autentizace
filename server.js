const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    pasword: "",
    database: "user_auth"
});

db.connect(err => {
    if (err) {
        console.log("Nastala chyba.:(", err);
    } else {
        console.log("Úspěšné přihlášení.:)")
    }
});

app.post("/register", (req, res) => {
    const { username, name, email, password } = req.body;

    if(!username || !email || !password) {
        return res.status(400).send('Missing required fields');
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send("Chyba při hašování hesla");

        const query = 'INSERT INTO users (username, name, email, password) VALUES (?, ?, ?, ?)';
        db.query(query, [username, name, email, hashedPassword], (err, result) => {
        if (err) return res.status(500).send('Error saving user');
        res.status(201).send('User registered successfully');
        });
    });
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if(!email || !password) {
        return res.status(400).send('Chybí email nebo heslo');
    }

    const query = "SELECT * FROM users WHERE email = ?";
    db.query(query, [email], (err, results) => {
        if (err) return res.status(500).send("Chyba při kontrole uživatele");
        if (results.length === 0) return res.status(400).send("Uživatel nenalezen");

        const user = results[0];
        bcrypt.compare(password, user.password, (err, match) => {
            if (err) return res.status(500).send("Chyba při porovnávání hesel");
            if (!match) return res.status(400).send("Neplatné přihlašovací údaje");

            const token = jwt.sign({ userId: user.id}, process.env.JWT_SECRET, { expiresIn: "1h"});
            res.json({token});
        });
    });
});

app.put("/user", (req, res) => {
    const { email, token, name, password } = req.body;

    if (!token) {
        return res.status(401).send("Chybí token pro autorizaci");
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).send("Invalidní token");

        const userId = decoded.userId();
        const query = 'UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?';
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) return res.status(500).send('Error hashing password');
            db.query(query, [name, email, hashedPassword, userId], (err, result) => {
                if (err) return res.status(500).send('Error updating user');
                res.send('User updated successfully');
            });
        });
    });
});

app.listen(port, () => {
    console.log("Server běží na ${port}");
});
