// server.js
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
const http = require("http");               // 1️⃣ HTTP server için
const { Server } = require("socket.io");    // 2️⃣ Socket.io

const app = express();                       // 3️⃣ Express app önce
const server = http.createServer(app);       // 4️⃣ Server sonra
const io = new Server(server, { cors: { origin: "*" } });  // 5️⃣ io en son

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


//socketim
io.on("connection", socket => {
    console.log("Yeni kullanıcı bağlandı:", socket.id);

   

    socket.on("disconnect", () => {
        console.log("Kullanıcı ayrıldı:", socket.id);
    });
});



// ----------------------------
// Register
// ----------------------------
// Register endpoint
app.post("/register", async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Email daha önce var mı kontrol et
        const existingUser = await pool.query(
            "SELECT id FROM users WHERE email=$1",
            [email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: "Email zaten kayıtlı." });
        }

        // 2. Şifreyi hashle
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Yeni kullanıcıyı ekle
        const newUser = await pool.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
            [email, hashedPassword]
        );

        const user = newUser.rows[0];

        // 4. Access ve refresh token oluştur
        const accessToken = jwt.sign(
            { id: user.id, email: user.email },
            ACCESS_SECRET,
            { expiresIn: "15m" }
        );
        const refreshToken = jwt.sign(
            { id: user.id, email: user.email },
            REFRESH_SECRET,
            { expiresIn: "7d" }
        );

        // 5. Client'a tokenları döndür
        res.json({
            accessToken,
            refreshToken
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Sunucu hatası." });
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
app.post("/refresh", (req, res) => { //buraya refresh tokenı gönderiyorsun
    const { token } = req.body; //json şeklinde refresh tokenı alıyorum burda
    if (!token) return res.sendStatus(401); //burda hata alırsak refresh tokenın süresi geçmiştir.logine atmam lazım kullanıcıyı

    jwt.verify(token, REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = jwt.sign({ id: user.id, email: user.email }, ACCESS_SECRET, { expiresIn: "15m" });
        res.json({ accessToken, refreshToken: token });
    });
});

// Kullanıcıları listele (kendin hariç)
// ----------------------------
app.get("/users", authenticate, async (req, res) => {
    try {
        const currentUserId = req.user.id;

        const result = await pool.query(
            "SELECT id, email FROM users WHERE id != $1",
            [currentUserId]
        );

        res.json(result.rows); // JSON array (liste) döner
    } catch (err) {
        console.error("Kullanıcıları getirirken hata:", err);
        res.status(500).json({ error: "Sunucu hatası" });
    }
});

app.get("/whoami", authenticate, (req, res) => {
    res.json({ id: req.user.id, email: req.user.email });
});

// ----------------------------
// Middleware: Access token doğrulama
// ----------------------------
function authenticate(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, ACCESS_SECRET, (err, user) => { //burda access tokeni veriyorum aslında.user dedigide accesstoken içindeki payload
        if (err) return res.sendStatus(401);
        req.user = user;  //req.user jwt kimlik dogrulaması eğer başarılıysa token içindeki payload bilgisini taşıyan yapı payload aslında json verisi taşıyor
        //request user jsonunu ekliyor aslında burda.
        next();
    });
}

// ----------------------------
// Korunan endpoint
// ----------------------------
app.get("/profile", authenticate, (req, res) => {
    res.json({ message: "Profil bilgileri", user: req.user });
});

server.listen(3000, () => console.log("Auth server 3000 portunda çalışıyor 🚀"));
