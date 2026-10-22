/**
 * AXRA V2 - Full Backend with Profiles, Stories, Posts, Reels
 * Ghana's Instagram - Built by Timm
 * Requirements: MONGODB_URI, JWT_SECRET, CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET
 */

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'axra_secret_ghana_2026';

// Cloudinary Config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Ensure public folder exists
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true });
app.use(express.static(publicDir));

// MongoDB Connect
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB Connected - Axra V2'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// Multer setup (memory storage for Cloudinary)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// Helper: Upload to Cloudinary
function uploadToCloudinary(fileBuffer, folder = 'axra') {
  return new Promise((resolve, reject) => {
    if (!process.env.CLOUDINARY_CLOUD_NAME) {
      // Fallback: save locally if no Cloudinary
      const filename = Date.now() + '-' + Math.random().toString(36).substring(7) + '.jpg';
      const filepath = path.join(publicDir, 'uploads', filename);
      if (!fs.existsSync(path.join(publicDir, 'uploads'))) fs.mkdirSync(path.join(publicDir, 'uploads'), { recursive: true });
      fs.writeFileSync(filepath, fileBuffer);
      return resolve({ secure_url: `/uploads/${filename}` });
    }
    const stream = cloudinary.uploader.upload_stream({ folder, resource_type: 'auto' }, (err, result) => {
      if (err) reject(err); else resolve(result);
    });
    stream.end(fileBuffer);
  });
}

// ===== SCHEMAS =====
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  fullName: { type: String, default: '' },
  email: { type: String, default: '' },
  bio: { type: String, default: '🇬🇭 Ghana • Axra user' },
  website: { type: String, default: '' },
  avatar: { type: String, default: '' },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  userAvatar: String,
  image: String,
  caption: String,
  location: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{ username: String, userAvatar: String, text: String, createdAt: { type: Date, default: Date.now } }],
  filter: { type: String, default: 'normal' },
}, { timestamps: true });

const StorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: String,
  userAvatar: String,
  image: String,
  viewedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  expiresAt: { type: Date, default: () => new Date(Date.now() + 24*60*60*1000), index: { expires: '24h' } },
}, { timestamps: true });

const MessageSchema = new mongoose.Schema({
  sender: String,
  receiver: String,
  text: String,
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);
const Story = mongoose.model('Story', StorySchema);
const Message = mongoose.model('Message', MessageSchema);

// Auth Middleware
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  } catch { return res.status(401).json({ error: 'Invalid token' }); }
}

// ===== AUTH ROUTES =====
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, fullName, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username & password required' });
    const exists = await User.findOne({ username: username.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Username taken' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      username: username.toLowerCase().trim(),
      password: hashed,
      fullName: fullName || username,
      email: email || '',
      avatar: `https://i.pravatar.cc/300?u=${username.toLowerCase()}`,
    });
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { _id: user._id, username: user.username, fullName: user.fullName, avatar: user.avatar, bio: user.bio, website: user.website, email: user.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user) return res.status(400).json({ error: 'User not found' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Wrong password' });
    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { _id: user._id, username: user.username, fullName: user.fullName, avatar: user.avatar, bio: user.bio, website: user.website, email: user.email } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== PROFILE ROUTES =====
app.get('/api/profile/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username.toLowerCase() });
    if (!user) return res.status(404).json({ error: 'Not found' });
    const posts = await Post.find({ userId: user._id }).sort({ createdAt: -1 });
    res.json({
      _id: user._id,
      username: user.username,
      fullName: user.fullName,
      avatar: user.avatar,
      bio: user.bio,
      website: user.website,
      followersCount: user.followers.length,
      followingCount: user.following.length,
      postsCount: posts.length,
      posts,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/profile', authMiddleware, upload.single('avatar'), async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { fullName, bio, website } = req.body;
    if (fullName) user.fullName = fullName;
    if (bio) user.bio = bio;
    if (website !== undefined) user.website = website;
    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer, 'axra/avatars');
      user.avatar = result.secure_url;
    }
    await user.save();
    res.json({ _id: user._id, username: user.username, fullName: user.fullName, avatar: user.avatar, bio: user.bio, website: user.website, email: user.email });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Follow / Unfollow
app.post('/api/profile/:username/follow', authMiddleware, async (req, res) => {
  try {
    const target = await User.findOne({ username: req.params.username.toLowerCase() });
    const me = await User.findById(req.userId);
    if (!target || !me) return res.status(404).json({ error: 'User not found' });
    if (target._id.equals(me._id)) return res.status(400).json({ error: "Can't follow yourself" });
    const isFollowing = me.following.includes(target._id);
    if (isFollowing) {
      me.following.pull(target._id); target.followers.pull(me._id);
    } else {
      me.following.push(target._id); target.followers.push(me._id);
    }
    await me.save(); await target.save();
    res.json({ following: !isFollowing, followersCount: target.followers.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== POSTS ROUTES =====
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find().sort({ createdAt: -1 }).limit(100);
    res.json(posts);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const { caption, location, filter } = req.body;
    let imageUrl = '';
    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer, 'axra/posts');
      imageUrl = result.secure_url;
    }
    if (!imageUrl && !caption) return res.status(400).json({ error: 'Image or caption required' });
    const post = await Post.create({
      userId: user._id,
      username: user.username,
      userAvatar: user.avatar,
      image: imageUrl,
      caption: caption || '',
      location: location || '',
      filter: filter || 'normal',
      likes: [],
      comments: [],
    });
    io.emit('newPost', post);
    res.json(post);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts/:id/like', authMiddleware, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const idx = post.likes.findIndex(id => id.toString() === req.userId);
    if (idx > -1) post.likes.splice(idx, 1); else post.likes.push(req.userId);
    await post.save();
    io.emit('likeUpdate', { postId: post._id, likes: post.likes });
    res.json(post);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/posts/:id/comment', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const comment = { username: user.username, userAvatar: user.avatar, text: req.body.text };
    post.comments.push(comment);
    await post.save();
    io.emit('commentUpdate', { postId: post._id, comments: post.comments });
    res.json(post);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Not found' });
    if (post.userId.toString() !== req.userId) return res.status(403).json({ error: 'Not yours' });
    await Post.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== STORIES ROUTES - NEW =====
app.get('/api/stories', async (req, res) => {
  try {
    // Only non-expired (Mongo TTL handles deletion but also filter)
    const stories = await Story.find({ expiresAt: { $gt: new Date() } }).sort({ createdAt: -1 }).limit(100);
    // Group by user for Instagram style
    const grouped = {};
    stories.forEach(s => {
      if (!grouped[s.userId]) grouped[s.userId] = { userId: s.userId, username: s.username, userAvatar: s.userAvatar, stories: [] };
      grouped[s.userId].stories.push(s);
    });
    res.json(Object.values(grouped));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stories', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    let imageUrl = '';
    if (req.file) {
      const result = await uploadToCloudinary(req.file.buffer, 'axra/stories');
      imageUrl = result.secure_url;
    }
    if (!imageUrl) return res.status(400).json({ error: 'Image required' });
    const story = await Story.create({
      userId: user._id,
      username: user.username,
      userAvatar: user.avatar,
      image: imageUrl,
    });
    io.emit('newStory', story);
    res.json(story);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/stories/:id/view', authMiddleware, async (req, res) => {
  try {
    const story = await Story.findById(req.params.id);
    if (!story) return res.status(404).json({ error: 'Not found' });
    if (!story.viewedBy.includes(req.userId)) {
      story.viewedBy.push(req.userId);
      await story.save();
    }
    res.json({ viewed: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ===== MESSAGES (DM) =====
app.get('/api/messages/:user', authMiddleware, async (req, res) => {
  try {
    const msgs = await Message.find({
      $or: [{ sender: req.username, receiver: req.params.user }, { sender: req.params.user, receiver: req.username }]
    }).sort({ createdAt: 1 }).limit(100);
    res.json(msgs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Socket.io
io.on('connection', socket => {
  console.log('User connected');
  socket.on('join', username => socket.join(username));
  socket.on('sendMessage', async data => {
    const msg = await Message.create(data);
    io.to(data.receiver).emit('receiveMessage', msg);
    io.to(data.sender).emit('receiveMessage', msg);
  });
  socket.on('disconnect', () => console.log('User disconnected'));
});

// Fallback to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

server.listen(PORT, () => console.log(`🚀 Axra V2 running on port ${PORT}`));
