const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const multer = require('multer');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
	cors: { origin: true, credentials: true },
	maxHttpBufferSize: 20 * 1024 * 1024
});

const JWT_SECRET = process.env.JWT_SECRET || 'axra_super_secret_v6_2024';
const INVITE_CODE = process.env.INVITE_CODE || 'AXRA2024';
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "20mb" }));
app.use(cookieParser());
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// --- AXRA PHOTO & STORY UPLOAD ---
const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
		cb(null, 'uploads/');
	},
	filename: (req, file, cb) => {
		cb(null, Date.now() + '-' + file.originalname.replace(/\s/g, '_'));
	}
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 }, fileFilter: (req, file, cb) => cb(null, true) });

app.post('/api/upload', upload.single('file'), (req, res) => {
	if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
	res.json({ url: `/uploads/${req.file.filename}`, filename: req.file.filename, type: req.file.mimetype, size: req.file.size });
});
// --- END UPLOAD ---

const DB_FILE = path.join(__dirname, "axra.json");
function loadDB() {
	try {
		if (!fs.existsSync(DB_FILE)) return { users: [], messages: [], groups: [], stories: [], privateMessages: {} };
		const raw = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
		if (!raw.stories) raw.stories = [];
		if (!raw.privateMessages) raw.privateMessages = {};
		if (!raw.groups) raw.groups = [];
		if (!raw.messages) raw.messages = [];
		return raw;
	} catch { return { users: [], messages: [], groups: [], stories: [], privateMessages: {} }; }
}
function saveDB(db) { try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); } catch {} }

function authMiddleware(req, res, next) {
	try {
		const token = (req.cookies && req.cookies.token) || req.headers.authorization?.replace("Bearer ", "") || req.query.token;
		if (!token) return res.status(401).json({ message: "No token" });
		req.user = jwt.verify(token, JWT_SECRET);
		next();
	} catch { return res.status(401).json({ message: "Invalid token" }); }
}

// ========== AUTH ==========
app.post('/api/register', (req, res) => {
	const { name, username, email, password, inviteCode } = req.body;
	if (!name ||!username ||!email ||!password) return res.status(400).json({ message: "All fields required" });
	if (INVITE_CODE && inviteCode!== INVITE_CODE) return res.status(400).json({ message: `Invite code is ${INVITE_CODE}` });
	const db = loadDB();
	if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase() || u.username.toLowerCase() === username.toLowerCase())) return res.status(400).json({ message: "User exists" });
	const user = { _id: Date.now().toString() + Math.random().toString(36).slice(2,6), name, username: username.toLowerCase(), email: email.toLowerCase(), password: bcrypt.hashSync(password, 8), createdAt: new Date().toISOString() };
	user.id = user._id;
	db.users.push(user); saveDB(db);
	const safe = { _id: user._id, id: user._id, name: user.name, username: user.username, email: user.email };
	const token = jwt.sign(safe, JWT_SECRET);
	res.cookie("token", token, { httpOnly: false }).json({ token, user: safe });
});

app.post('/api/auth/login', (req, res) => {
	const { username, email } = req.body;
	const loginName = (username || email || "").toLowerCase();
	if (!loginName) return res.status(400).json({ message: "Username required" });
	const db = loadDB();
	let user = db.users.find(u => u.username.toLowerCase() === loginName || u.email.toLowerCase() === loginName);
	if (!user) {
		user = { _id: Date.now().toString() + Math.random().toString(36).slice(2,6), name: username||email, username: loginName, email: loginName+"@axra.chat", password: bcrypt.hashSync("axra123", 8), createdAt: new Date().toISOString() };
		user.id = user._id; db.users.push(user); saveDB(db);
	}
	const safe = { _id: user._id, id: user._id, name: user.name, username: user.username, email: user.email };
	const token = jwt.sign(safe, JWT_SECRET);
	res.cookie("token", token, { httpOnly: false }).json({ token, user: safe });
});
app.post('/api/login', (req, res) => {
	req.body.username = req.body.username || req.body.email;
	return app._router.stack.find(l => l.route && l.route.path === '/api/auth/login').handle(req, res);
});

// ========== USERS & GROUPS ==========
app.get('/api/users', authMiddleware, (req, res) => {
	const db = loadDB();
	res.json(db.users.map(u => ({ _id: u._id, id: u._id, name: u.name, username: u.username, email: u.email })));
});
app.get('/api/groups', authMiddleware, (req, res) => res.json(loadDB().groups || []));
app.post('/api/groups', authMiddleware, (req, res) => {
	const { name } = req.body; if (!name) return res.status(400).json({ message: "Name required" });
	const db = loadDB();
	const group = { _id: Date.now().toString(), id: Date.now().toString(), name, members: [req.user._id], createdBy: req.user._id, createdAt: new Date().toISOString(), messages: [] };
	db.groups.push(group); saveDB(db); io.emit('newGroup', group); res.json(group);
});

// ========== STORIES ==========
app.get('/api/stories', authMiddleware, (req, res) => {
	const db = loadDB();
	const now = Date.now();
	const valid = (db.stories||[]).filter(s => (now - new Date(s.createdAt).getTime()) < 24*60*60*1000);
	if (valid.length!== (db.stories||[]).length) { db.stories = valid; saveDB(db); }
	res.json(valid);
});
app.post('/api/stories', authMiddleware, (req, res) => {
	const { image, text } = req.body; if (!image) return res.status(400).json({ message: "Image required" });
	const db = loadDB();
	const story = { _id: Date.now().toString(), id: Date.now().toString(), userId: req.user._id, username: req.user.username, name: req.user.name, image, text: text||"", createdAt: new Date().toISOString() };
	db.stories.unshift(story); if (db.stories.length>100) db.stories = db.stories.slice(0,100); saveDB(db); io.emit('newStory', story); res.json(story);
});

// ========== MESSAGES ==========
app.get('/api/messages/global', authMiddleware, (req, res) => res.json(loadDB().messages || []));
app.post('/api/messages/global', authMiddleware, (req, res) => {
	const { text, image, type } = req.body; if (!text &&!image) return res.status(400).json({ message: "Empty" });
	const db = loadDB();
	const msg = { _id: Date.now().toString()+Math.random().toString(36).slice(2,5), sender: req.user._id, sender_id: req.user._id, sender_username: req.user.username, sender_name: req.user.name, text: text||"", message: text||"", image: image||null, type: type||(image?'image':'text'), createdAt: new Date().toISOString(), timestamp: new Date().toISOString() };
	db.messages.push(msg); if (db.messages.length>500) db.messages=db.messages.slice(-500); saveDB(db); io.emit('newMessage', { type:'global', message:msg }); res.json(msg);
});
app.get('/api/messages/private/:id', authMiddleware, (req, res) => {
	const otherId=req.params.id; const myId=req.user._id; const db=loadDB();
	const key1=`${myId}_${otherId}`; const key2=`${otherId}_${myId}`;
	res.json(db.privateMessages || db.privateMessages || []);
});
app.post('/api/messages/private/:id', authMiddleware, (req, res) => {
	const otherId=req.params.id; const myId=req.user._id; const { text, image, type } = req.body; if (!text &&!image) return res.status(400).json({ message: "Empty" });
	const db=loadDB();
	const msg={ _id:Date.now().toString()+Math.random().toString(36).slice(2,5), sender:myId, sender_id:myId, sender_username:req.user.username, sender_name:req.user.name, receiver:otherId, receiver_id:otherId, text:text||"", message:text||"", image:image||null, type:type||(image?'image':'text'), createdAt:new Date().toISOString(), timestamp:new Date().toISOString() };
	const key1=`${myId}_${otherId}`; const key2=`${otherId}_${myId}`; const existingKey=db.privateMessages?key1:(db.privateMessages?key2:key1);
	if(!db.privateMessages[existingKey]) db.privateMessages[existingKey]=[]; db.privateMessages[existingKey].push(msg); if(db.privateMessages[existingKey].length>500) db.privateMessages[existingKey]=db.privateMessages[existingKey].slice(-500); saveDB(db);
	io.emit('newMessage', { type:'private', from:myId, to:otherId, message:msg }); res.json(msg);
});
app.get('/api/messages/group/:id', authMiddleware, (req, res) => {
	const db=loadDB(); const group=db.groups.find(g=>g._id===req.params.id||g.id===req.params.id); if(!group) return res.status(404).json({ message:"Group not found" }); res.json(group.messages||[]);
});
app.post('/api/messages/group/:id', authMiddleware, (req, res) => {
	const { text, image, type } = req.body; if(!text &&!image) return res.status(400).json({ message:"Empty" });
	const db=loadDB(); const group=db.groups.find(g=>g._id===req.params.id||g.id===req.params.id); if(!group) return res.status(404).json({ message:"Group not found" });
	const msg={ _id:Date.now().toString(), sender:req.user._id, sender_id:req.user._id, sender_username:req.user.username, sender_name:req.user.name, text:text||"", message:text||"", image:image||null, type:type||(image?'image':'text'), createdAt:new Date().toISOString(), timestamp:new Date().toISOString() };
	if(!group.messages) group.messages=[]; group.messages.push(msg); if(group.messages.length>500) group.messages=group.messages.slice(-500); saveDB(db); io.emit('newMessage', { type:'group', groupId:group._id, message:msg }); res.json(msg);
});

// ========== SOCKET.IO ==========
const onlineUsers=new Map();
io.on('connection',(socket)=>{
	socket.on('join',(userId)=>{ onlineUsers.set(userId,socket.id); socket.userId=userId; io.emit('userOnline',userId); });
	socket.on('call-user',(data)=>{ const s=onlineUsers.get(data.to); if(s) io.to(s).emit('incoming-call',{from:data.from,video:data.video}); });
	socket.on('accept-call',(data)=>{ const s=onlineUsers.get(data.to); if(s) io.to(s).emit('call-accepted',{from:socket.userId}); });
	socket.on('end-call',(data)=>{ const s=onlineUsers.get(data.to); if(s) io.to(s).emit('call-ended',{from:socket.userId}); });
	socket.on('webrtc-offer',(data)=>{ const s=onlineUsers.get(data.to); if(s) io.to(s).emit('webrtc-offer',data); });
	socket.on('webrtc-answer',(data)=>{ const s=onlineUsers.get(data.to); if(s) io.to(s).emit('webrtc-answer',data); });
	socket.on('ice-candidate',(data)=>{ const s=onlineUsers.get(data.to); if(s) io.to(s).emit('ice-candidate',data); });
	socket.on('disconnect',()=>{ if(socket.userId){ onlineUsers.delete(socket.userId); io.emit('userOffline',socket.userId); } });
});

app.get('/',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
server.listen(PORT,()=>console.log(`🔥 Axra V6 Final running on http://localhost:${PORT} - Photos, Calls, Stories enabled`));
