const express = require('express');
const app = express();
var Filter = require('bad-words');
var customFilter = new Filter({ placeHolder: '*'});
app.all("*", (req, res, next) => {
  console.log("\nPage: " + req.path + "\nMethod: " + req.method)
  
  next()
})
require('dotenv').config()
const { v4: uuidv4 } = require('uuid');
//const bodyParser = require('body-parser')
var cookieSession = require('cookie-session')
const crypto = require("crypto");
app.use(express.json());
app.use(express.urlencoded());
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const mongoose = require('mongoose')
const io = new Server(server);

mongoose.connect(process.env.MongooseURI);
function removeDashes(key){
  return key.replace(/-/g, '')
}
 
const accessSchema = new mongoose.Schema({
  key: String,
  valid: Boolean
})
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  created: Date,
  banned: Boolean,
  warn: Boolean,
  warns: Object,
  admin: Boolean
})
const messageSchema = new mongoose.Schema({
  message: String,
  created: Date,
  author: String,
  deleted: Boolean,
  messageId: Number
})
const session = cookieSession({
  name: 'CookieSession',
  keys: [process.env.CookieSession],

  // Cookie Options
  maxAge: 24 * 60 * 60 * 1000
})
const messageModel = mongoose.model("messages", messageSchema)
const accessModel = mongoose.model("AccessKeys", accessSchema)
const userModel = mongoose.model("Users", userSchema)
app.use(session)
app.set('view engine', 'ejs');

function signedin(req, res, next) {
  if(req.session.user){
    next()
  }
  else {
    res.render(__dirname + "/ejs/lockscreen.ejs")
  }
}
app.use("/images", express.static('images'))
app.use("/css", express.static('css'))
app.use("/js", express.static('js'))
app.get('/home', (req, res) => {
  res.render(__dirname + "/ejs/home.ejs")
})
app.get('/', (req, res) => {
  if(req.session.user) {
    res.redirect("/home")
  } else {
  res.render(__dirname + '/ejs/index.ejs');
  }
});
app.get('/logout', (req, res) => {
  req.session.user = undefined
  res.redirect("/")
})
app.get("/requestaccess", (req, res)=>{
  res.render(__dirname + "/ejs/access.ejs", {msg: ""})
})
app.post("/requestaccess", async (req, res) => {
  try {
    
  
  const keys = await accessModel.find({ key: removeDashes(req.body.key), valid: true })
  const key = keys[0]
  if(key){
    
    key.valid = false
    await key.save()
    req.session.access = true
    res.redirect('/signup')
    
  }
  else {
    res.render(__dirname + "/ejs/access.ejs", {msg: "Invalid Key"})
  }
} catch (errMsg) {console.dir(errMsg)}
})
app.get("/signup", (req, res) => {

  if(req.session.access !== true){
    res.redirect('/requestaccess')
  }
  else {
  res.render(__dirname + "/ejs/signup.ejs", {msg: ""})
  }
  
})
app.post("/signup", async (req, res) => {
  try {
  const users = await userModel.find({username: req.body.username.toLowerCase()});
  const foundUser = users[0]
  if(!foundUser) {
    req.session.access = false
    
const sha256Hasher = crypto.createHash("sha256", process.env.cryptoSecret);
    const user = new userModel({username: req.body.username.toLowerCase(), password: sha256Hasher.update(req.body.password).digest("hex"), banned: false, warn: false, created: Date.now()})
  await user.save()
  
  res.redirect("/login")
  } else {
    res.render(__dirname + "/ejs/signup.ejs", {msg: "Our systems just found that this user exists already! Try a new username :)"})
  }
} catch{}
})

app.get("/chat", signedin, async function(req, res, next) {
  try {
  var messages = await messageModel.find({deleted: false})
  res.render(__dirname + "/ejs/chat.ejs", {msgs: messages, usr: req.session.user})
  } catch{}
})

app.get("/createkey", (req, res) => {
  res.render(__dirname + "/ejs/createkey.ejs")
})
app.post("/createkey", async (req, res)=>{
  try {
    if(req.body.pass == process.env.OwnerPass){
      const key = uuidv4()
      const newKey = new accessModel({ key: removeDashes(key), valid: true })
      await newKey.save()
      res.send(key)
    } else {
      res.send("Nice try.")
    }
  } catch (errMsg) {console.dir(errMsg)}
})
app.get("/login", (req, res) => {
  res.render(__dirname + "/ejs/login.ejs", {msg: ""})
})

app.post("/login", async (req, res) => {
const sha256Hasher = crypto.createHash("sha256", process.env.cryptoSecret);
  try {
  const users = await userModel.find({username: req.body.username.toLowerCase(), password: sha256Hasher.update(req.body.password).digest("hex")});
  const foundUser = users[0]
  if(!foundUser) {
    res.render(__dirname + "/ejs/login.ejs", {msg: "Our systems couldn't find a match for this login! Try again :)"})
  } else {
    req.session.user = req.body.username.toLowerCase()
    res.redirect("/home")
  } }catch (errMsg) {console.dir(errMsg)}})
io.on('connection', (socket) => {
  let cookieString = socket.request.headers.cookie;

    let req = {connection: {encrypted: false}, headers: {cookie: cookieString}}
    let res = {getHeader: () =>{}, setHeader: () => {}};
    //
    session(req, res, () => {
         // Do something with req.session
    
  console.log("Connected!")
  socket.on("cliMsg", async (message) => {
    try {
    const isAdmin = await userModel.find({username: req.session.user, admin: true, banned: false})
    if(message.startsWith("!")){
      const args = message.slice(0).trim().split(/ +/);
    const cmd = args.shift().toLowerCase();
    const argsJoined = message.slice(cmd.length + 1)
      if(cmd == "!eval" && isAdmin[0]){
        var results
        try {
          results = await eval(argsJoined)
          
          let msgObj = {message: results, username: "✔️Eval"}
        io.emit('serverMsg', msgObj)
        }
        catch (e) {
          let msgObj = {message: e.toString(), username: "❌Eval"}
        io.emit('serverMsg', msgObj)
        }
        
      }
    } else {
    var realMessage = message.replaceAll('\n', "<br>").trim("<br>")
    var lastMessage = messageModel.find({})
    var newMsgId = (await lastMessage).length
    var newMsg = new messageModel({message: customFilter.clean(realMessage), author: req.session.user, sent: Date.now(), deleted: false, messageId: newMsgId })
    await newMsg.save()
    let msgObj = {message: customFilter.clean(realMessage), username: req.session.user, messageId: newMsgId}
    io.emit('serverMsg', msgObj)
    }} catch (errMsg) {console.dir(errMsg)}
  });
  socket.on("delMsg", async (msgId) => {
    try {
    var msgs = await messageModel.find({messageId: msgId, deleted: false})
    var msg = msgs[0]
    if(!msg) {return};
    var msgAuthor = msg.author
    if(msgAuthor !== req.session.user) {return}
    msg.deleted = true
    await msg.save()
    io.emit('serverDelMsg', msgId)
    } catch (errMsg) {console.dir(errMsg)}
  })
  socket.on('disconnect', () => {
    console.log('Disconnected.');
  });
})
});


io.of("/home").on("connection", (socket) => {
  console.log('hi')
});
app.all("*", (req, res) => {
    res.status(400);
    res.render(__dirname + "/ejs/errorpage.ejs", {errorCode: "400 Bad Request"});
   });
server.listen(80, () => {
  console.log('listening on localhost');
})