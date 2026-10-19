// Axrachat - Complete Backend Server
// npm install express socket.io mongoose bcryptjs jsonwebtoken multer cors dotenv

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'axrachat_super_secret_2026';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/axrachat';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static('uploads'));

let useMemoryDB = true;
const memoryDB = { users: [], posts: [], stories: [], messages: [] };

mongoose.connect(MONGO_URI).then(() => {
	useMemoryDB = false;
	console.log('MongoDB Connected');
}).catch(() => console.log('Using in-memory DB'));

// Models
const UserSchema = new mongoose.Schema({
	username: { unique: true, type: String },
	email: String, password: String, fullName: String,
	bio: { type: String, default: '' },
	avatar: String, followers: [], following: [],
	createdAt: { type: Date, default: Date.now }
});
const PostSchema = new mongoose.Schema({
	user: String, username: String, userAvatar: String,
	image: String, caption: String,
	likes: [], comments: [], createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);

const auth = (req,res,next) => {
	const token = req.headers.authorization?.split(' ')[1];
	if(!token) return res.status(401).json({error:'No token'});
	try { req.user = jwt.verify(token, JWT_SECRET); next(); }
	catch { res.status(401).json({error:'Invalid'}); }
};

const storage = multer.diskStorage({
	destination: (req,file,cb) => cb(null, 'uploads/'),
	filename: (req,file,cb) => cb(null, Date.now()+path.extname(file.originalname))
});
const upload = multer({ storage });

// AUTH
app.post('/api/auth/register', async (req,res) => {
	const { username, email, password, fullName } = req.body;
	const hashed = await bcrypt.hash(password, 10);
	if(useMemoryDB){
		if(memoryDB.users.find(u=>u.username===username)) return res.status(400).json({error:'Taken'});
		const user = { _id: Date.now().toString(), username, email, password: hashed, fullName, avatar: `https://i.pravatar.cc/150?u=${username}`, followers:[], following:[] };
		memoryDB.users.push(user);
		const token = jwt.sign({id:user._id, username}, JWT_SECRET);
		return res.json({ token, user });
	}
	const user = await User.create({ username, email, password: hashed, fullName });
	const token = jwt.sign({id:user._id, username}, JWT_SECRET);
	res.json({ token, user });
});

app.post('/api/auth/login', async (req,res) => {
	const { username, password } = req.body;
	let user = useMemoryDB ? memoryDB.users.find(u=>u.username===username) : await User.findOne({username});
	if(!user) return res.status(400).json({error:'Not found'});
	const ok = await bcrypt.compare(password, user.password);
	if(!ok) return res.status(400).json({error:'Wrong password'});
	const token = jwt.sign({id:user._id, username:user.username}, JWT_SECRET);
	res.json({ token, user });
});

// POSTS
app.get('/api/posts', async (req,res) => {
	if(useMemoryDB) return res.json(memoryDB.posts.slice().reverse());
	res.json(await Post.find().sort({createdAt:-1}).limit(50));
});

app.post('/api/posts', auth, upload.single('image'), async (req,res) => {
	const image = req.file ? `/uploads/${req.file.filename}` : req.body.image || `https://picsum.photos/600/600?random=${Date.now()}`;
	const post = { _id: Date.now().toString(), username: req.user.username, userAvatar: `https://i.pravatar.cc/150?u=${req.user.username}`, image, caption: req.body.caption, likes:[], comments:[], createdAt: new Date() };
	if(useMemoryDB) memoryDB.posts.push(post); else await Post.create(post);
	io.emit('newPost', post);
	res.json(post);
});

app.post('/api/posts/:id/like', auth, async (req,res) => {
	const post = memoryDB.posts.find(p=>p._id===req.params.id);
	if(!post) return res.status(404).json({error:'Not found'});
	const i = post.likes.indexOf(req.user.id);
	if(i>-1) post.likes.splice(i,1); else post.likes.push(req.user.id);
	io.emit('likeUpdate', {postId: post._id, likes: post.likes});
	res.json(post);
});

app.post('/api/posts/:id/comment', auth, async (req,res) => {
	const post = memoryDB.posts.find(p=>p._id===req.params.id);
	post.comments.push({ username: req.user.username, text: req.body.text, createdAt: new Date() });
	io.emit('commentUpdate', post);
	res.json(post);
});

// MESSAGES REALTIME
io.on('connection', (socket) => {
	socket.on('sendMessage', (data) => {
		memoryDB.messages.push(data);
		io.emit('receiveMessage', data);
	});
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

server.listen(PORT, () => console.log(`🚀 Axrachat running http://localhost:${PORT}`));
