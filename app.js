// Notes: Make a collection of DMS, and each dm would have a list of participants.

const express = require('express');
const app = express();
var md = new require('markdown-it')();
var Filter = require('bad-words');
var customFilter = new Filter({ placeHolder: '*' });
app.all("*", (req, res, next) => {
  console.log("\nPage: " + req.path + "\nMethod: " + req.method)

  next()
})
require('dotenv').config()
const { v4: uuidv4, v1: uuidv1 } = require('uuid');
//const bodyParser = require('body-parser')
var cookieSession = require('cookie-session')
const crypto = require("crypto");
app.use(express.json());
app.use(express.urlencoded());
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const mongoose = require('mongoose')
const { instrument } = require("@socket.io/admin-ui");
const io = new Server(server, {
  cors: {
    origin: ["https://admin.socket.io"],
    credentials: true
  }
});
instrument(io, {
  auth: {
    type: "basic",
    username: "admin",
    password: process.env.OwnerPassEncrypted // "changeit" encrypted with bcrypt
  },
});
mongoose.connect(process.env.MongooseURI);
function removeDashes(key) {
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
  admin: Boolean,
  dms: Array
})
const dmSchema = new mongoose.Schema({
  users: Array,
  dmId: String,
  dmSecret: String,
  messages: Array
})
const messageSchema = new mongoose.Schema({
  message: String,
  for: String,
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
const dmModel = mongoose.model("Dms", dmSchema)
const userModel = mongoose.model("Users", userSchema)
app.use(session)
app.set('view engine', 'ejs');
async function test223(){
  console.dir(await userModel.findOne({username: 'test222'}))
}
test223()
function signedin(req, res, next) {
  if (req.session.user) {
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
  if (req.session.user) {
    res.redirect("/home")
  } else {
    res.render(__dirname + '/ejs/index.ejs');
  }
});
app.get('/logout', (req, res) => {
  req.session.user = undefined
  res.redirect("/")
})
app.get("/requestaccess", (req, res) => {
  res.render(__dirname + "/ejs/access.ejs", { msg: "" })
})
app.post("/requestaccess", async (req, res) => {
  try {


    const keys = await accessModel.find({ key: removeDashes(req.body.key), valid: true })
    const key = keys[0]
    if (key) {

      key.valid = false
      await key.save()
      req.session.access = true
      res.redirect('/signup')

    }
    else {
      res.render(__dirname + "/ejs/access.ejs", { msg: "Invalid Key" })
    }
  } catch (errMsg) { console.dir(errMsg) }
})
app.get("/signup", (req, res) => {

  if (req.session.access !== true) {
    res.redirect('/requestaccess')
  }
  else {
    res.render(__dirname + "/ejs/signup.ejs", { msg: "" })
  }

})
app.get("/chat/menu", signedin, async (req, res) => {

  res.render(__dirname + "/ejs/chathome.ejs")
})
app.get("/chat/createDms", signedin, (req, res) => {
  res.render(__dirname + "/ejs/createDms.ejs")
})
app.get("/chat/dms", signedin, async (req, res) => {
  function arrayRemove(arr, value) { 
    
    return arr.filter(function(ele){ 
        return ele != value; 
    });
}
  const user = await userModel.find({ username: req.session.user })
  if (!user[0]) {
    return
  }
  if (!user[0].dms) {
    res.render(__dirname + "/ejs/dms.ejs", { requests: [] })
  }
  else {
    console.log('a')
    var userDms = user[0].dms
    
    var resObj = []
    userDms.forEach(async (v, i) => {
      console.log(v)
      var thisDm = await dmModel.find({dmId: v})
      if(!thisDm[0]) {return console.dir(v)}
      var dmUsers = thisDm[0].users
var dmUserName = arrayRemove(dmUsers, req.session.user)
      resObj[i] = {id: v, username: dmUserName}
    });
    
    res.render(__dirname + "/ejs/dms.ejs", { requests: resObj })
  }
})
app.post("/chat/addDms", signedin, async (req, res) => {
  var dmUser = req.body.username
  if (!dmUser) {
    return
  }
  var dmUserV = await userModel.find({ username: dmUser })
  if (!dmUserV[0]) {
    return res.render(__dirname + "/ejs/createDms.ejs", { errorMessage: "User not found." })
  }
  else {

  }
})
// app.get("/chat/requests",signedin, async(req, res) => {
//   var User = await userModel.find({username: req.session.user})
//   if(!User[0]){
//     return;
//   }
//   var friends = User[0].friendrequests
//   res.render(__dirname + "/ejs/friendrequests.ejs", {requests: friends})
// })
// app.get("/chat/addfriends", signedin, (req, res) => {
//   res.render(__dirname + "/ejs/addfriends.ejs")
// })
// app.post("/chat/addfriends", async (req, res) => {
//   var friendName = req.body.username
//   console.dir(friendName)
//   if(!friendName) {
//     return res.redirect("/400")
//   }
//   if(typeof(friendName) !== "string") {
//     return res.redirect("/400")
//   }
//   friendName = friendName.toLowerCase()
//   var friend = await userModel.find({ username: friendName })
//   if(!friend[0]) {
//     return res.render(__dirname + "/ejs/addfriends.ejs", {errorMessage: "User does not exist"})
//   }
//   else {
//     if(!friend[0].friendrequests){
//       friend[0].friendrequests = [req.session.user]
//     }
//     else {
//       if(friend[0].friendrequests.includes(req.session.user)){
//         return res.render(__dirname + "/ejs/addfriends.ejs", {errorMessage: `You already sent a request to this person!`})
//       }
//       else if(friend[0].username == req.session.user){
//         return res.render(__dirname + "/ejs/addfriends.ejs", {errorMessage: `You can't send a friend request to yourself!`})

//       }

//       friend[0].friendrequests = friend[0].friendrequests.push(req.session.user)
//     }
//     await friend[0].save()
//     return res.render(__dirname + "/ejs/addfriends.ejs", {successMessage: `Friend request sent to ${friendName}!`})

//   }
// })
app.post("/signup", async (req, res) => {
  try {
    const users = await userModel.find({ username: req.body.username.toLowerCase() });
    const foundUser = users[0]
    if (!foundUser) {
      req.session.access = false

      const sha256Hasher = crypto.createHash("sha256", process.env.cryptoSecret);
      const user = new userModel({ username: req.body.username.toLowerCase(), password: sha256Hasher.update(req.body.password).digest("hex"), banned: false, warn: false, created: Date.now() })
      await user.save()

      res.redirect("/login")
    } else {
      res.render(__dirname + "/ejs/signup.ejs", { msg: "Our systems just found that this user exists already! Try a new username :)" })
    }
  } catch { }
})

// app.get("/chat", signedin, async function(req, res, next) {
//   try {
//   var messages = await messageModel.find({deleted: false})
//   res.render(__dirname + "/ejs/chat.ejs", {msgs: messages, usr: req.session.user})
//   } catch{}
// })
app.get("/chat", signedin, async function (req, res, next) {
  try {
    var messages = await messageModel.find({ deleted: false })
    res.render(__dirname + "/ejs/chat.ejs", { msgs: [{
       message: "<h1>Welcome to <strong>Spacemessaging</strong>!</h1>", author: "[Owner] Cheslin23t", messageId: -1 },
        { message: "<h2>Start by <a href='/chat/createDms'>Creating a DM</a>!</h2>", author: "[Owner] Cheslin23t", messageId: -1 
      }, {message: "<h3>Have fun chatting!</h3>", author: "[Owner] Cheslin23t", messageId: -1}], usr: req.session.user })
  } catch { }
})
app.get("/createkey", (req, res) => {
  res.render(__dirname + "/ejs/createKey.ejs")
})
app.post("/createkey", async (req, res) => {
  try {
    if (req.body.pass == process.env.OwnerPass) {
      const key = uuidv4()
      const newKey = new accessModel({ key: removeDashes(key), valid: true })
      await newKey.save()
      var Jimp = require("jimp");

      var fileName = __dirname + '/images/spacemsginginvite.png';
      var imageCaption = key;
      var loadedImage;

      Jimp.read(fileName)
        .then(function (image) {
          loadedImage = image;
          return Jimp.loadFont(Jimp.FONT_SANS_16_BLACK);
        })
        .then(function (font) {
          loadedImage.print(font, 250, 325, imageCaption, 600, 100)
            .write(__dirname + '/images/newInvite.png');
          res.redirect('/images/newInvite.png')
        })
        .catch(function (err) {
          console.error(err);
        });
      // res.send(key)
    } else {
      res.send("Nice try.")
    }
  } catch (errMsg) { console.dir(errMsg) }
})
app.get("/login", (req, res) => {
  res.render(__dirname + "/ejs/login.ejs", { msg: "" })
})
app.post('/chat/adddm', signedin, async (req, res) => {
  if(!req.body.username) return
  if(!typeof(req.body.username) == "string") return
  if(req.session.user == req.body.username.toLowerCase()) {
    return res.render(__dirname + "/ejs/createDms.ejs", {msg: "You can't create a dm to yourself!"})
  }
  const cliUser = await userModel.find({username: req.session.user})
  const friend = await userModel.find({username: req.body.username.toLowerCase()})
  if(!cliUser[0]) {
    return res.redirect("/server-confused")
  }
  if(!friend[0]) {
    return res.render(__dirname + "/ejs/createDms.ejs", {msg: "User does not exist."})
  }
  // Please ignore the hacky method below
  const ifDmExists = await dmModel.find({users: [req.session.user, friend[0].username]})
  const ifDmExists2 = await dmModel.find({users: [friend[0].username, req.session.user]})
  if(ifDmExists[0] || ifDmExists2[0]) {
    return res.render(__dirname + "/ejs/createDms.ejs", {msg: "Already created a DM for this user!"})
  }
  const newDmID = uuidv1()
  const newDm = new dmModel({dmId: newDmID, users: [req.session.user, friend[0].username], dmSecret: uuidv4()})
  await newDm.save()
  
  var x = friend[0].dms
  var y = cliUser[0].dms
  x = ( typeof x != 'undefined' && x instanceof Array ) ? x : []
  x = x.push(newDmID)

  y = ( typeof y != 'undefined' && y instanceof Array ) ? y : []
  y = y.push(newDmID)
  await cliUser[0].save()
  await friend[0].save()
  res.redirect('/chat/dms/' + newDmID)
})
app.post("/login", async (req, res) => {
  const sha256Hasher = crypto.createHash("sha256", process.env.cryptoSecret);
  try {
    const users = await userModel.find({ username: req.body.username.toLowerCase(), password: sha256Hasher.update(req.body.password).digest("hex") });
    const foundUser = users[0]
    if (!foundUser) {
      res.render(__dirname + "/ejs/login.ejs", { msg: "Our systems couldn't find a match for this login! Try again :)" })
    } else {
      req.session.user = req.body.username.toLowerCase()
      res.redirect("/home")
    }
  } catch (errMsg) { console.dir(errMsg) }
})
io.on('connection', (socket) => {
  const CryptoJS = require('crypto-js');

  const encrypt = (text, secret) => {
    return CryptoJS.AES.encrypt(text, secret).toString();
  };

  const decrypt = (data, secret) => {
    var bytes = CryptoJS.AES.decrypt(data, secret);
    return bytes.toString(CryptoJS.enc.Utf8);
  };

  let cookieString = socket.request.headers.cookie;

  let req = { connection: { encrypted: false }, headers: { cookie: cookieString } }
  let res = { getHeader: () => { }, setHeader: () => { } };
  //
  session(req, res, () => {
    // Do something with req.session

    console.log("Connected!")
    socket.on("cliMsg", async (message, dmId) => {
      if (!req.session.user) return;
      if (!dmId) return;
      var dmV = await dmModel.find({ dmId: dmId })
      if (!dmV[0]) return;
      if (!dmV[0].users.includes(req.session.user)) return
      var decryptCode = dmV[0].dmSecret

      try {
        const isAdmin = await userModel.find({ username: req.session.user, admin: true, banned: false })
        if (message.startsWith("!")) {
          const args = message.slice(0).trim().split(/ +/);
          const cmd = args.shift().toLowerCase();
          const argsJoined = message.slice(cmd.length + 1)
          if (cmd == "!eval" && isAdmin[0]) {
            var results
            try {
              results = await eval(argsJoined)

              let msgObj = { message: encrypt(results, decryptCode), username: "✔️Eval" }
              io.emit('serverMsg', msgObj)
            }
            catch (e) {
              let msgObj = { message: e.toString(), username: "❌Eval" }
              io.emit('serverMsg', msgObj)
            }

          }
        } else {


          console.dir(message)
          var newMessage = md.render(message);
          console.dir(newMessage)
          var realMessage = newMessage.substring(0, newMessage.length - 1).replaceAll("\n", "<br />").replaceAll("<p>", "<span>").replaceAll('</p>', '</span>')
          console.dir(realMessage)
          var lastMessage = messageModel.find({})
          var newMsgId = (await lastMessage).length

          let msgObj = { message: customFilter.clean(realMessage), username: req.session.user, messageId: newMsgId }
          io.emit('serverMsg', msgObj)
          var newMsg = new messageModel({ message: customFilter.clean(realMessage), author: req.session.user, sent: Date.now(), deleted: false, messageId: newMsgId })
          await newMsg.save()
        }
      } catch (errMsg) { console.dir(errMsg) }
    });
    socket.on("delMsg", async (msgId) => {
      try {
        var msgs = await messageModel.find({ messageId: msgId, deleted: false })
        var msg = msgs[0]
        if (!msg) { return };
        var msgAuthor = msg.author
        if (msgAuthor !== req.session.user) { return }
        msg.deleted = true
        io.emit('serverDelMsg', msgId)
        await msg.save()

      } catch (errMsg) { console.dir(errMsg) }
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
  res.render(__dirname + "/ejs/errorpage.ejs", { errorCode: "400 Bad Request" });
});
server.listen(80, () => {
  console.log('listening on localhost');
})
