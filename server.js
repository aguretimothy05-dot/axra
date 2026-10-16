require("dotenv").config();
const path = require("path");
const http = require("http");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { Server } = require("socket.io");

const PORT = Number(process.env.PORT) || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "AxraFinal2026SuperSecretKey123";
const INVITE_CODE = process.env.INVITE_CODE || "AXRA2026";

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true }, maxHttpBufferSize: 20e6 });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "20mb" }));
app.use(cookieParser());
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy:false }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const DB_FILE = path.join(__dirname, "axra.json");
function loadDB(){
	try{
		const raw = JSON.parse(fs.readFileSync(DB_FILE,"utf8"));
		return {
			users: raw.users||[],
			global_messages: raw.global_messages||[],
			private_messages: raw.private_messages||[],
			groups: raw.groups||[],
			group_messages: raw.group_messages||[],
			group_members: raw.group_members||[]
		};
	}catch{ return { users:[], global_messages:[], private_messages:[], groups:[], group_messages:[], group_members:[] }; }
}
function saveDB(d){ fs.writeFileSync(DB_FILE, JSON.stringify(d,null,2)); }
let db = loadDB();

function createToken(u){ return jwt.sign({id:u.id, username:u.username}, JWT_SECRET, {expiresIn:"7d"}); }
function authMiddleware(req,res,next){
	try{
		const token = (req.cookies && req.cookies.token) || (req.headers.authorization||"").replace("Bearer ","") || req.query.token;
		if(!token) return res.status(401).json({message:"No token"});
		req.user = jwt.verify(token, JWT_SECRET);
		next();
	}catch{ return res.status(401).json({message:"Invalid token"}); }
}

const storage = multer.diskStorage({
	destination: (req,file,cb)=>cb(null, path.join(__dirname,"uploads")),
	filename: (req,file,cb)=>cb(null, Date.now()+"-"+file.originalname.replace(/\s+/g,"_"))
});
const upload = multer({ storage, limits:{fileSize:20*1024*1024}, fileFilter:(req,file,cb)=>{
	if(file.mimetype.startsWith("image/") || file.mimetype.startsWith("audio/") || file.mimetype.startsWith("video/")) cb(null,true);
	else cb(new Error("Only media allowed"));
}});

app.post(["/api/register","/register"],(req,res)=>{
	try{
		const {name,username,email,country,password,inviteCode}=req.body;
		if(!name||!username||!email||!password) return res.status(400).json({message:"All fields required"});
		if(password.length<6) return res.status(400).json({message:"Password min 6"});
		if(inviteCode!==INVITE_CODE) return res.status(400).json({message:`Invite code is ${INVITE_CODE}`});
		db=loadDB();
		if(db.users.find(u=>u.email===email.toLowerCase()||u.username===username.toLowerCase())) return res.status(400).json({message:"Username or email taken"});
		const user={id:Date.now(), name:name.trim(), username:username.toLowerCase().trim(), email:email.toLowerCase().trim(), country:country||"Ghana", password:bcrypt.hashSync(password,10), created_at:new Date().toISOString()};
		db.users.push(user); saveDB(db);
		const safe={id:user.id,name:user.name,username:user.username,email:user.email,country:user.country};
		const token=createToken(safe);
		res.cookie("token",token,{httpOnly:true,maxAge:7*24*60*60*1000,sameSite:"lax"});
		return res.status(201).json({token,user:safe});
	}catch(e){ return res.status(500).json({message:e.message}); }
});
app.post(["/api/login","/login"],(req,res)=>{
	try{
		const {email,username,password}=req.body;
		const val=(email||username||"").toLowerCase().trim();
		if(!val||!password) return res.status(400).json({message:"Missing"});
		db=loadDB();
		const full=db.users.find(u=>u.email===val||u.username===val);
		if(!full) return res.status(400).json({message:"User not found"});
		if(!bcrypt.compareSync(password,full.password)) return res.status(400).json({message:"Wrong password"});
		const safe={id:full.id,name:full.name,username:full.username,email:full.email,country:full.country};
		const token=createToken(safe);
		res.cookie("token",token,{httpOnly:true,maxAge:7*24*60*60*1000,sameSite:"lax"});
		return res.json({token,user:safe});
	}catch(e){ return res.status(500).json({message:e.message}); }
});
app.get("/api/me",authMiddleware,(req,res)=>{
	db=loadDB();
	const u=db.users.find(x=>x.id===req.user.id);
	if(!u) return res.status(404).json({message:"User not found"});
	return res.json({user:{id:u.id,name:u.name,username:u.username,email:u.email,country:u.country}});
});
app.get("/api/users",authMiddleware,(req,res)=>{
	db=loadDB();
	return res.json({users:db.users.filter(u=>u.id!==req.user.id).map(u=>({id:u.id,name:u.name,username:u.username,country:u.country}))});
});
app.get("/api/global-messages",authMiddleware,(req,res)=>{
	db=loadDB();
	const msgs=db.global_messages.slice(-300).map(m=>({...m, username:db.users.find(x=>x.id===m.user_id)?.username||"unknown"}));
	return res.json({messages:msgs});
});
app.get("/api/private-messages/:userId",authMiddleware,(req,res)=>{
	db=loadDB();
	const otherId=Number(req.params.userId);
	const msgs=db.private_messages.filter(m=>(m.sender_id===req.user.id&&m.receiver_id===otherId)||(m.sender_id===otherId&&m.receiver_id===req.user.id)).slice(-300);
	return res.json({messages:msgs});
});

// GROUPS
app.post("/api/groups",authMiddleware,(req,res)=>{
	db=loadDB();
	const {name, memberIds} = req.body;
	if(!name) return res.status(400).json({message:"Group name required"});
	const group = {id:Date.now(), name:name.trim(), created_by:req.user.id, created_at:new Date().toISOString()};
	db.groups.push(group);
	const members = [...new Set([req.user.id,...(memberIds||[]).map(Number)])];
	members.forEach(uid=>db.group_members.push({group_id:group.id, user_id:uid}));
	saveDB(db);
	return res.json({group});
});
app.get("/api/groups",authMiddleware,(req,res)=>{
	db=loadDB();
	const myGroupIds = db.group_members.filter(gm=>gm.user_id===req.user.id).map(gm=>gm.group_id);
	const myGroups = db.groups.filter(g=>myGroupIds.includes(g.id));
	return res.json({groups:myGroups});
});
app.get("/api/group-messages/:groupId",authMiddleware,(req,res)=>{
	db=loadDB();
	const gid = Number(req.params.groupId);
	const isMember = db.group_members.some(gm=>gm.group_id===gid && gm.user_id===req.user.id);
	if(!isMember) return res.status(403).json({message:"Not member"});
	const msgs = db.group_messages.filter(m=>m.group_id===gid).slice(-300);
	return res.json({messages:msgs});
});
app.post("/api/upload", authMiddleware, upload.single("image"), (req,res)=>{
	if(!req.file) return res.status(400).json({message:"No file"});
	return res.json({url:`/uploads/${req.file.filename}`});
});

io.use((socket,next)=>{
	try{
		const token=socket.handshake.auth.token || socket.handshake.query.token;
		if(!token) return next(new Error("No token"));
		socket.user=jwt.verify(token,JWT_SECRET);
		next();
	}catch{ next(new Error("Auth error")); }
});

const onlineUsers=new Map();
io.on("connection",(socket)=>{
	onlineUsers.set(socket.user.id, socket.user.username);
	io.emit("online-users", Array.from(onlineUsers.entries()).map(([id,username])=>({id,username})));

	socket.on("global-message",(data)=>{
		db=loadDB();
		const msg={id:Date.now(), user_id:socket.user.id, message:data.message||"", image:data.image||null, created_at:new Date().toISOString()};
		db.global_messages.push(msg); saveDB(db);
		io.emit("global-message",{...msg, username:db.users.find(x=>x.id===socket.user.id)?.username||socket.user.username});
	});
	socket.on("private-message",(data)=>{
		db=loadDB();
		const msg={id:Date.now(), sender_id:socket.user.id, receiver_id:Number(data.receiver_id), message:data.message||"", image:data.image||null, created_at:new Date().toISOString()};
		db.private_messages.push(msg); saveDB(db);
		for(let [sid,s] of io.sockets.sockets){
			if(s.user && (s.user.id===msg.receiver_id || s.user.id===msg.sender_id)) s.emit("private-message",msg);
		}
	});
	socket.on("group-message",(data)=>{
		db=loadDB();
		const gid=Number(data.group_id);
		const isMember=db.group_members.some(gm=>gm.group_id===gid && gm.user_id===socket.user.id);
		if(!isMember) return;
		const msg={id:Date.now(), group_id:gid, sender_id:socket.user.id, sender_username:socket.user.username, message:data.message||"", image:data.image||null, created_at:new Date().toISOString()};
		db.group_messages.push(msg); saveDB(db);
		const memberIds=db.group_members.filter(gm=>gm.group_id===gid).map(gm=>gm.user_id);
		for(let [sid,s] of io.sockets.sockets){
			if(s.user && memberIds.includes(s.user.id)) s.emit("group-message",msg);
		}
	});

	// CALLING SIGNALING
	socket.on("call-user",({to, offer, type})=>{
		for(let [sid,s] of io.sockets.sockets){
			if(s.user && s.user.id===Number(to)){
				s.emit("incoming-call",{from:socket.user.id, fromUsername:socket.user.username, offer, type});
			}
		}
	});
	socket.on("answer-call",({to, answer})=>{
		for(let [sid,s] of io.sockets.sockets){
			if(s.user && s.user.id===Number(to)) s.emit("call-answered",{from:socket.user.id, answer});
		}
	});
	socket.on("ice-candidate",({to, candidate})=>{
		for(let [sid,s] of io.sockets.sockets){
			if(s.user && s.user.id===Number(to)) s.emit("ice-candidate",{from:socket.user.id, candidate});
		}
	});
	socket.on("end-call",({to})=>{
		for(let [sid,s] of io.sockets.sockets){
			if(s.user && s.user.id===Number(to)) s.emit("call-ended",{from:socket.user.id});
		}
	});

	socket.on("disconnect",()=>{
		onlineUsers.delete(socket.user.id);
		io.emit("online-users", Array.from(onlineUsers.entries()).map(([id,username])=>({id,username})));
	});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
server.listen(PORT,()=>console.log(`✅ AXRA+MEDIA V4 GROUPS+CALLING on http://localhost:${PORT}`));
