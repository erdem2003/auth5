// server.js
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// PostgreSQL bağlantısı
const pool = new Pool({
    connectionString: "postgresql://retrofit_user:chFpvHU03RtwYXQKsemsja80Dc6tHjVZ@dpg-d37snfruibrs739ajgt0-a.frankfurt-postgres.render.com/retrofit",
    ssl: { rejectUnauthorized: false }
});

pool.connect()
    .then(() => console.log("PostgreSQL'e bağlandı"))
    .catch(err => console.error("DB bağlantı hatası:", err));

// JWT secret
const ACCESS_SECRET = "supersecretaccess";
const REFRESH_SECRET = "supersecretrefresh";

// Kullanıcı tablosu (PostgreSQL)
// CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL);

// ----------------------------
// Register
// ----------------------------
app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashed = await bcrypt.hash(password, 10);
        const result = await pool.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
            [email, hashed]
        );
        res.json({ user: result.rows[0] });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// ----------------------------
// Login
// ----------------------------
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: "Şifre yanlış" });

        const accessToken = jwt.sign({ id: user.id, email: user.email }, ACCESS_SECRET, { expiresIn: "15m" });
        const refreshToken = jwt.sign({ id: user.id, email: user.email }, REFRESH_SECRET, { expiresIn: "7d" });

        res.json({ accessToken, refreshToken });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ----------------------------
// Refresh token
// ----------------------------
app.post("/refresh", (req, res) => {
    const { token } = req.body;
    if (!token) return res.sendStatus(401);

    jwt.verify(token, REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = jwt.sign({ id: user.id, email: user.email }, ACCESS_SECRET, { expiresIn: "15m" });
        res.json({ accessToken, refreshToken: token });
    });
});

// ----------------------------
// Middleware: Access token doğrulama
// ----------------------------
function authenticate(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, ACCESS_SECRET, (err, user) => {
        if (err) return res.sendStatus(401);
        req.user = user;
        next();
    });
}

// ----------------------------
// Korunan endpoint
// ----------------------------
app.get("/profile", authenticate, (req, res) => {
    res.json({ message: "Profil bilgileri", user: req.user });
});

app.listen(3000, () => console.log("Auth server 3000 portunda çalışıyor 🚀"));
