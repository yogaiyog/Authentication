import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv"
import bcrypt from "bcrypt"
import session from "express-session"
import passport from "passport"
import { Strategy } from "passport-local";

const saltRounds = 10;
env.config()

const db = new pg.Client({
  user:process.env.DB_USER,
  database:process.env.DB,
  host:process.env.DB_HOST,
  password:process.env.DB_PASSWORD,
  port:process.env.DB_PORT,
})

const app = express();
const port = 3000;
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000*60*60*24 },
}))

app.use(passport.initialize());
app.use(passport.session());

db.connect((err)=> {
  if (err) throw err;
  console.log("Connected to DataBase!");
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/secrets", (req,res)=>{
  console.log(req.user)
  if (req.isAuthenticated()){
    res.render("secrets.ejs")
  }else{
    res.redirect("/login")
  }
})

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  var username = req.body.username
  var pwd = req.body.password

  try {
    const checkEmail =  await db.query(`select * from student where email = $1`, [username]) //ambil user berdasarkan email
    if (checkEmail.rows.length == 0) {                                                       //check apa user ada
      bcrypt.hash(pwd, saltRounds, async (err,hash)=>{                                       //hasing password
        if (err) {console.log("error hasing password:",err)}
        else {
          const result = await db.query("INSERT INTO student (email , password) VALUES ($1 , $2) returning *",[username , hash]) // jika ada data dimasukan ke row baru
          const user = result.rows[0]
          req.login(user, (err)=>{
            if (err) {
              console.log("login error:",err)
            } else {
              console.log("success")
              res.redirect("/secrets")
            }
          })
        }
      })
    } 
    else {
      res.send("<strong>email sudah terdaftar</strong>") // jika tidak menemukan user di database
    }
  } 
  catch (err) {
    console.log(err)  //jika gagal konek ke database
  }
});

app.post("/login",passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
}))

passport.use(new Strategy(async function verify (username, password, cb) {
  try {
    var result = await db.query("SELECT * FROM student WHERE email = $1", [username])
    const user = result.rows
    if (user.length > 0) {                      
      var userStoredPassword = result.rows[0].password
      bcrypt.compare(password,userStoredPassword,(err,same)=>{
        if (err) {
          console.error("error comparing password",err)
          return cb(err)
        }
        else {
          if (same) {
            return cb(null, user)
          }
          else {
            return cb(null,false)
          }}
      })  
    }
    else {
      res.render("home.ejs",{message:"email anda belum terdaftar"})
    }
  } 
  catch(err) {
    console.log(err)
  }
}))

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
