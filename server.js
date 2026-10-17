require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = Number(process.env.PORT) || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const INVITE_CODE = process.env.INVITE_CODE;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
	throw new Error("Set JWT_SECRET to a random secret of at least 32 characters in .env");
}

if (!INVITE_CODE) {
	throw new Error("Set INVITE_CODE in your .env file");
}

// Middleware
app.use(helmet({
	contentSecurityPolicy: false
}));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use("/api", rateLimit({
	windowMs: 15 * 60 * 1000,
	limit: 150,
	standardHeaders: true,
	legacyHeaders: false
}));

// Database
const db = new Database("axraconnect.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		username TEXT NOT NULL COLLATE NOCASE UNIQUE,
		email TEXT NOT NULL COLLATE NOCASE UNIQUE,
		country TEXT NOT NULL,
		password_hash TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender_id INTEGER NOT NULL REFERENCES users(id),
		receiver_id INTEGER NOT NULL REFERENCES users(id),
		text TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS messages_conversation_idx
	ON messages(sender_id, receiver_id, id);

	CREATE TABLE IF NOT EXISTS friend_requests (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender_id INTEGER NOT NULL REFERENCES users(id),
		receiver_id INTEGER NOT NULL REFERENCES users(id),
		status TEXT NOT NULL DEFAULT 'pending',
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(sender_id, receiver_id)
	);
`);

// Authentication helpers
function createToken(user) {
	return jwt.sign(
		{ id: user.id },
		JWT_SECRET,
		{ expiresIn: "7d" }
	);
}

function publicUser(user) {
	return {
		id: user.id,
		name: user.name,
		username: user.username,
		email: user.email,
		country: user.country,
		createdAt: user.created_at
	};
}

function setAuthCookie(res, user) {
	res.cookie("axra_token", createToken(user), {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
		maxAge: 7 * 24 * 60 * 60 * 1000,
		path: "/"
	});
}

function authenticate(req, res, next) {
	const token = req.cookies.axra_token;

	if (!token) {
		return res.status(401).json({
			message: "Please sign in first."
		});
	}

	try {
		const payload = jwt.verify(token, JWT_SECRET);
		const user = db.prepare(
			"SELECT * FROM users WHERE id = ?"
		).get(payload.id);

		if (!user) {
			return res.status(401).json({
				message: "Account not found."
			});
		}

		req.user = user;
		next();
	} catch {
		return res.status(401).json({
			message: "Your session has expired. Please sign in again."
		});
	}
}

// Health check
app.get("/api/health", (req, res) => {
	res.json({
		status: "ok",
		message: "AxraConnect server is running."
	});
});

// REGISTER
app.post("/api/register", async (req, res) => {
	try {
		const {
			name,
			username,
			email,
			country,
			password,
			inviteCode
		} = req.body || {};

		if (
			!name || !username || !email ||
			!country || !password || !inviteCode
		) {
			return res.status(400).json({
				message: "Please complete all registration fields."
			});
		}

		if (
			name.trim().length < 2 ||
			username.trim().length < 3 ||
			username.trim().length > 30 ||
			!/^[a-zA-Z0-9_.]+$/.test(username.trim()) ||
			!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
			country.trim().length < 2
		) {
			return res.status(400).json({
				message: "Check your name, username, email and country."
			});
		}

		if (password.length < 10) {
			return res.status(400).json({
				message: "Password must contain at least 10 characters."
			});
		}

		if (password.length > 128) {
			return res.status(400).json({
				message: "Password is too long."
			});
		}

		if (inviteCode !== INVITE_CODE) {
			return res.status(403).json({
				message: "Invalid invitation code."
			});
		}

		const cleanName = name.trim();
		const cleanUsername = username.trim();
		const cleanEmail = email.trim().toLowerCase();
		const cleanCountry = country.trim();

		const existing = db.prepare(`
			SELECT id FROM users
			WHERE username = ? OR email = ?
		`).get(cleanUsername, cleanEmail);

		if (existing) {
			return res.status(409).json({
				message: "That username or email is already registered."
			});
		}

		const passwordHash = await bcrypt.hash(password, 12);

		const result = db.prepare(`
			INSERT INTO users
			(name, username, email, country, password_hash)
			VALUES (?, ?, ?, ?, ?)
		`).run(
			cleanName,
			cleanUsername,
			cleanEmail,
			cleanCountry,
			passwordHash
		);

		const user = db.prepare(
			"SELECT * FROM users WHERE id = ?"
		).get(result.lastInsertRowid);

		setAuthCookie(res, user);

		return res.status(201).json({
			message: "Account created successfully.",
			user: publicUser(user)
		});
	} catch (error) {
		if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
			return res.status(409).json({
				message: "That username or email is already registered."
			});
		}

		console.error("Registration error:", error);

		return res.status(500).json({
			message: "Registration failed. Check the server terminal."
		});
	}
});

// LOGIN
app.post("/api/login", async (req, res) => {
	try {
		const { email, password } = req.body || {};

		if (!email || !password) {
			return res.status(400).json({
				message: "Enter your email and password."
			});
		}

		const user = db.prepare(`
			SELECT * FROM users WHERE email = ?
		`).get(String(email).trim().toLowerCase());

		if (!user || !(await bcrypt.compare(password, user.password_hash))) {
			return res.status(401).json({
				message: "Incorrect email or password."
			});
		}

		setAuthCookie(res, user);

		return res.json({
			message: "Login successful.",
			user: publicUser(user)
		});
	} catch (error) {
		console.error("Login error:", error);
		return res.status(500).json({
			message: "Login failed."
		});
	}
});

// CURRENT USER
app.get("/api/me", authenticate, (req, res) => {
	res.json({ user: publicUser(req.user) });
});

// LOGOUT
app.post("/api/logout", (req, res) => {
	res.clearCookie("axra_token", {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
		path: "/"
	});

	res.json({ message: "Signed out successfully." });
});

// SEARCH USERS
app.get("/api/users", authenticate, (req, res) => {
	const query = String(req.query.q || "").trim().slice(0, 50);

	const users = db.prepare(`
		SELECT id, name, username, country, created_at
		FROM users
		WHERE id != ?
			AND (
				username LIKE ? ESCAPE '\\'
				OR name LIKE ? ESCAPE '\\'
				OR country LIKE ? ESCAPE '\\'
			)
		ORDER BY username
		LIMIT 50
	`).all(
		req.user.id,
		`%${query.replace(/[\\%_]/g, "\\$&")}%`,
		`%${query.replace(/[\\%_]/g, "\\$&")}%`,
		`%${query.replace(/[\\%_]/g, "\\$&")}%`
	);

	res.json({ users });
});

// SEND FRIEND REQUEST
app.post("/api/friends/request", authenticate, (req, res) => {
	const receiverId = Number(req.body?.receiverId);

	if (!Number.isInteger(receiverId) || receiverId < 1 ||
			receiverId === req.user.id) {
		return res.status(400).json({
			message: "Choose a valid user."
		});
	}

	const receiver = db.prepare(
		"SELECT id FROM users WHERE id = ?"
	).get(receiverId);

	if (!receiver) {
		return res.status(404).json({
			message: "User not found."
		});
	}

	try {
		db.prepare(`
			INSERT INTO friend_requests (sender_id, receiver_id)
			VALUES (?, ?)
		`).run(req.user.id, receiverId);

		res.status(201).json({
			message: "Friend request sent."
		});
	} catch (error) {
		if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
			return res.status(409).json({
				message: "You have already sent a request to this user."
			});
		}
		throw error;
	}
});

// VIEW FRIEND REQUESTS
app.get("/api/friends/requests", authenticate, (req, res) => {
	const requests = db.prepare(`
		SELECT fr.id, fr.sender_id AS senderId,
					 u.name, u.username, u.country, fr.created_at AS createdAt
		FROM friend_requests fr
		JOIN users u ON u.id = fr.sender_id
		WHERE fr.receiver_id = ? AND fr.status = 'pending'
		ORDER BY fr.id DESC
	`).all(req.user.id);

	res.json({ requests });
});

// ACCEPT FRIEND REQUEST
app.post("/api/friends/accept", authenticate, (req, res) => {
	const requestId = Number(req.body?.requestId);

	const result = db.prepare(`
		UPDATE friend_requests
		SET status = 'accepted'
		WHERE id = ? AND receiver_id = ? AND status = 'pending'
	`).run(requestId, req.user.id);

	if (!result.changes) {
		return res.status(404).json({
			message: "Pending friend request not found."
		});
	}

	res.json({ message: "Friend request accepted." });
});

// VIEW CONVERSATION
app.get("/api/messages/:userId", authenticate, (req, res) => {
	const otherId = Number(req.params.userId);

	if (!Number.isInteger(otherId) || otherId < 1 ||
			otherId === req.user.id) {
		return res.status(400).json({
			message: "Invalid conversation."
		});
	}

	const otherUser = db.prepare(
		"SELECT id FROM users WHERE id = ?"
	).get(otherId);

	if (!otherUser) {
		return res.status(404).json({
			message: "User not found."
		});
	}

	const messages = db.prepare(`
		SELECT id, sender_id AS senderId,
					 receiver_id AS receiverId, text,
					 created_at AS createdAt
		FROM messages
		WHERE (sender_id = ? AND receiver_id = ?)
			 OR (sender_id = ? AND receiver_id = ?)
		ORDER BY id DESC
		LIMIT 100
	`).all(req.user.id, otherId, otherId, req.user.id);

	res.json({ messages: messages.reverse() });
});

// SEND MESSAGE (HTTP alternative)
app.post("/api/messages", authenticate, (req, res) => {
	const receiverId = Number(req.body?.receiverId);
	const text = String(req.body?.text || "").trim();

	if (!Number.isInteger(receiverId) || receiverId < 1 ||
			receiverId === req.user.id) {
		return res.status(400).json({
			message: "Choose a valid recipient."
		});
	}

	if (!text || text.length > 2000) {
		return res.status(400).json({
			message: "Message must contain 1–2000 characters."
		});
	}

	const recipient = db.prepare(
		"SELECT id FROM users WHERE id = ?"
	).get(receiverId);

	if (!recipient) {
		return res.status(404).json({
			message: "Recipient not found."
		});
	}

	const result = db.prepare(`
		INSERT INTO messages (sender_id, receiver_id, text)
		VALUES (?, ?, ?)
	`).run(req.user.id, receiverId, text);

	const message = db.prepare(`
		SELECT id, sender_id AS senderId,
					 receiver_id AS receiverId, text,
					 created_at AS createdAt
		FROM messages WHERE id = ?
	`).get(result.lastInsertRowid);

	io.to(`user:${receiverId}`).emit("private_message", message);
	io.to(`user:${req.user.id}`).emit("private_message", message);

	res.status(201).json({ message });
});

// REAL-TIME SOCKET AUTHENTICATION
io.use((socket, next) => {
	try {
		const token = socket.handshake.headers.cookie
			?.split("; ")
			.find(item => item.startsWith("axra_token="))
			?.slice("axra_token=".length);

		if (!token) return next(new Error("Please sign in again."));

		const payload = jwt.verify(
			decodeURIComponent(token),
			JWT_SECRET
		);

		const user = db.prepare(
			"SELECT id, name, username FROM users WHERE id = ?"
		).get(payload.id);

		if (!user) return next(new Error("Account not found."));

		socket.user = user;
		next();
	} catch {
		next(new Error("Authentication failed."));
	}
});

const onlineUsers = new Map();

io.on("connection", socket => {
	const userId = socket.user.id;

	socket.join(`user:${userId}`);

	onlineUsers.set(userId, (onlineUsers.get(userId) || 0) + 1);

	if (onlineUsers.get(userId) === 1) {
		io.emit("user_online", { userId });
	}

	socket.emit("online_users", {
		userIds: Array.from(onlineUsers.keys())
	});

	socket.on("private_message", data => {
		const receiverId = Number(data?.receiverId);
		const text = String(data?.text || "").trim();

		if (
			!Number.isInteger(receiverId) ||
			receiverId < 1 ||
			receiverId === userId ||
			!text ||
			text.length > 2000
		) {
			return socket.emit("chat_error", {
				message: "Invalid recipient or message."
			});
		}

		const recipient = db.prepare(
			"SELECT id FROM users WHERE id = ?"
		).get(receiverId);

		if (!recipient) {
			return socket.emit("chat_error", {
				message: "Recipient not found."
			});
		}

		const result = db.prepare(`
			INSERT INTO messages (sender_id, receiver_id, text)
			VALUES (?, ?, ?)
		`).run(userId, receiverId, text);

		const message = db.prepare(`
			SELECT id, sender_id AS senderId,
						 receiver_id AS receiverId, text,
						 created_at AS createdAt
			FROM messages WHERE id = ?
		`).get(result.lastInsertRowid);

		io.to(`user:${receiverId}`).emit("private_message", message);
		io.to(`user:${userId}`).emit("private_message", message);
	});

	socket.on("typing", data => {
		const receiverId = Number(data?.receiverId);
		if (Number.isInteger(receiverId) && receiverId > 0 &&
				receiverId !== userId) {
			io.to(`user:${receiverId}`).emit("typing", {
				userId,
				username: socket.user.username
			});
		}
	});

	socket.on("stop_typing", data => {
		const receiverId = Number(data?.receiverId);
		if (Number.isInteger(receiverId) && receiverId > 0 &&
				receiverId !== userId) {
			io.to(`user:${receiverId}`).emit("stop_typing", { userId });
		}
	});

	socket.on("disconnect", () => {
		const count = (onlineUsers.get(userId) || 1) - 1;

		if (count <= 0) {
			onlineUsers.delete(userId);
			io.emit("user_offline", { userId });
		} else {
			onlineUsers.set(userId, count);
		}
	});
});

// Handle unknown API routes
app.use("/api", (req, res) => {
	res.status(404).json({
		message: `API route not found: ${req.method} ${req.path}`
	});
});

// Error handler
app.use((error, req, res, next) => {
	console.error("Server error:", error);

	if (res.headersSent) return next(error);

	res.status(500).json({
		message: "An unexpected server error occurred."
	});
});

server.listen(PORT, () => {
	console.log(`AxraConnect server running at http://localhost:${PORT}`);
});
