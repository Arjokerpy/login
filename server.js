const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const DB_FILE = path.join(__dirname, "data", "users.json");

// ---- ذخیره‌سازی ساده در فایل JSON ----
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "[]");
const readUsers = () => JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
const writeUsers = (users) => fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));

// ---- کمکی‌ها ----
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function setSession(res, user) {
  const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: "7d" });
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });

// ---- اپ ----
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/signup", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (name.length < 2) return res.status(400).json({ error: "نام باید حداقل ۲ حرف باشد." });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "ایمیل معتبر نیست." });
  if (password.length < 8) return res.status(400).json({ error: "رمز عبور باید حداقل ۸ کاراکتر باشد." });

  const users = readUsers();
  if (users.some((u) => u.email === email))
    return res.status(409).json({ error: "با این ایمیل قبلاً ثبت‌نام شده است." });

  const user = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
    name,
    email,
    passwordHash: await bcrypt.hash(password, 10),
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  writeUsers(users);

  setSession(res, user);
  res.status(201).json({ user: publicUser(user) });
});

app.post("/api/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const user = readUsers().find((u) => u.email === email);
  const ok = user && (await bcrypt.compare(password, user.passwordHash));
  if (!ok) return res.status(401).json({ error: "ایمیل یا رمز عبور اشتباه است." });

  setSession(res, user);
  res.json({ user: publicUser(user) });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  try {
    const { id } = jwt.verify(req.cookies.token, SECRET);
    const user = readUsers().find((u) => u.id === id);
    if (!user) throw new Error("not found");
    res.json({ user: publicUser(user) });
  } catch {
    res.status(401).json({ user: null });
  }
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
