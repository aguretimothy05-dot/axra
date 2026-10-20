// Axrachat - Backend Server
// npm install express socket.io mongoose bcryptjs jsonwebtoken multer cors dotenv

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: process.env.CLIENT_ORIGIN || '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'axrachat_development_secret_change_me';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/axrachat';
const uploadsDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));

let useMemoryDB = true;
const memoryDB = { users: [], posts: [], messages: [] };

mongoose.connect(MONGO_URI).then(() => {
	useMemoryDB = false;
	console.log('MongoDB connected');
}).catch((error) => {
	console.warn('Using in-memory DB:', error.message);
});

const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({
	username: { type: String, unique: true, required: true },
	email: { type: String, required: true },
	password: { type: String, required: true },
	fullName: String,
	bio: { type: String, default: '' },
	avatar: String,
	followers: { type: [String], default: [] },
	following: { type: [String], default: [] },
	createdAt: { type: Date, default: Date.now }
}));

const Post = mongoose.models.Post || mongoose.model('Post', new mongoose.Schema({
	user: String,
	username: String,
	userAvatar: String,
	image: String,
	caption: String,
	likes: { type: [String], default: [] },
	comments: { type: [mongoose.Schema.Types.Mixed], default: [] },
	createdAt: { type: Date, default: Date.now }
}));

const auth = (req, res, next) => {
	const token = req.headers.authorization?.split(' ')[1];
	if (!token) return res.status(401).json({ error: 'No token' });
	try {
		req.user = jwt.verify(token, JWT_SECRET);
		next();
	} catch {
		res.status(401).json({ error: 'Invalid token' });
	}
};

const storage = multer.diskStorage({
	destination: (_req, _file, cb) => cb(null, uploadsDir),
	filename: (_req, file, cb) => cb(null, `${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({
	storage,
	limits: { fileSize: 10 * 1024 * 1024 },
	fileFilter: (_req, file, cb) => {
		if (file.mimetype.startsWith('image/')) return cb(null, true);
		cb(new Error('Only image uploads are allowed'));
	}
});

app.post('/api/auth/register', async (req, res) => {
	try {
		const { username, email, password, fullName } = req.body || {};
		if (!username || !email || !password) {
			return res.status(400).json({ error: 'Username, email, and password are required' });
		}
		const existing = useMemoryDB
			? memoryDB.users.find((u) => u.username === username || u.email === email)
			: await User.findOne({ $or: [{ username }, { email }] });
		if (existing) return res.status(400).json({ error: 'Username or email is taken' });

		const user = {
			_id: new mongoose.Types.ObjectId().toString(), username, email,
			password: await bcrypt.hash(password, 10), fullName,
			avatar: `https://i.pravatar.cc/150?u=${encodeURIComponent(username)}`,
			followers: [], following: []
		};
		if (useMemoryDB) memoryDB.users.push(user);
		else await User.create(user);
		const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: '7d' });
		const { password: _password, ...safeUser } = user;
		res.status(201).json({ token, user: safeUser });
	} catch {
		res.status(500).json({ error: 'Registration failed' });
	}
});

app.post('/api/auth/login', async (req, res) => {
	try {
		const { username, password } = req.body || {};
		const user = useMemoryDB
			? memoryDB.users.find((u) => u.username === username)
			: await User.findOne({ username });
		if (!user || !await bcrypt.compare(password || '', user.password)) {
			return res.status(400).json({ error: 'Invalid username or password' });
		}
		const token = jwt.sign({ id: user._id.toString(), username: user.username }, JWT_SECRET, { expiresIn: '7d' });
		const safeUser = user.toObject ? user.toObject() : { ...user };
		delete safeUser.password;
		res.json({ token, user: safeUser });
	} catch {
		res.status(500).json({ error: 'Login failed' });
	}
});

app.get('/api/posts', async (_req, res) => {
	try {
		const posts = useMemoryDB
			? memoryDB.posts.slice().reverse().slice(0, 50)
			: await Post.find().sort({ createdAt: -1 }).limit(50);
		res.json(posts);
	} catch {
		res.status(500).json({ error: 'Could not load posts' });
	}
});

app.post('/api/posts', auth, upload.single('image'), async (req, res) => {
	try {
		const image = req.file
			? `/uploads/${req.file.filename}`
			: req.body.image || `https://picsum.photos/600/600?random=${Date.now()}`;
		const user = useMemoryDB
			? memoryDB.users.find((u) => u._id === req.user.id)
			: await User.findById(req.user.id);
		const postData = {
			user: req.user.id,
			username: req.user.username,
			userAvatar: user?.avatar || `https://i.pravatar.cc/150?u=${encodeURIComponent(req.user.username)}`,
			image,
			caption: req.body.caption || '',
			likes: [],
			comments: [],
			createdAt: new Date()
		};
		let post;
		if (useMemoryDB) {
			post = { _id: new mongoose.Types.ObjectId().toString(), ...postData };
			memoryDB.posts.push(post);
		} else {
			post = await Post.create(postData);
		}
		io.emit('newPost', post);
		res.status(201).json(post);
	} catch {
		res.status(500).json({ error: 'Could not create post' });
	}
});

app.post('/api/posts/:id/like', auth, async (req, res) => {
	try {
		const post = useMemoryDB
			? memoryDB.posts.find((p) => p._id === req.params.id)
			: await Post.findById(req.params.id);
		if (!post) return res.status(404).json({ error: 'Post not found' });
		const index = post.likes.indexOf(req.user.id);
		if (index > -1) post.likes.splice(index, 1);
		else post.likes.push(req.user.id);
		if (!useMemoryDB) await post.save();
		io.emit('likeUpdate', { postId: post._id, likes: post.likes });
		res.json(post);
	} catch {
		res.status(500).json({ error: 'Could not update like' });
	}
});

app.post('/api/posts/:id/comment', auth, async (req, res) => {
	try {
		const text = req.body?.text?.trim();
		if (!text) return res.status(400).json({ error: 'Comment text is required' });
		const post = useMemoryDB
			? memoryDB.posts.find((p) => p._id === req.params.id)
			: await Post.findById(req.params.id);
		if (!post) return res.status(404).json({ error: 'Post not found' });
		post.comments.push({ username: req.user.username, text, createdAt: new Date() });
		if (!useMemoryDB) await post.save();
		io.emit('commentUpdate', post);
		res.json(post);
	} catch {
		res.status(500).json({ error: 'Could not add comment' });
	}
});

io.on('connection', (socket) => {
	socket.on('sendMessage', (data) => {
		if (!data || typeof data !== 'object') return;
		memoryDB.messages.push(data);
		io.emit('receiveMessage', data);
	});
});

app.use((error, _req, res, _next) => {
	if (error instanceof multer.MulterError || error.message === 'Only image uploads are allowed') {
		return res.status(400).json({ error: error.message });
	}
	res.status(500).json({ error: 'Internal server error' });
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

server.listen(PORT, () => console.log(`Axrachat running at http://localhost:${PORT}`));
