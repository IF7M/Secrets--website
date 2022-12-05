
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
const Port = process.env.PORT;

app.use(express.json());   
app.use(express.static('public'));
app.use(function (req, res, next) {
    res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.header('Expires', '-1');
    res.header('Pragma', 'no-cache');
    next();
});
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
    secret: process.env.SECRETPASS,
    resave: false,
    saveUninitialized: false,
    
  }));
  app.use(passport.initialize());
  app.use(passport.session());

mongoose.connect(process.env.DBLINK, {useNewUrlParser: true, useUnifiedTopology: true });


const usersSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: []
});


usersSchema.plugin(passportLocalMongoose);
usersSchema.plugin(findOrCreate);


const User = new mongoose.model('User', usersSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:4000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user, created) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:4000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user, created) {
      return cb(err, user);
    });
  }
));

app.get('/', (req, res)=>{
    res.render('home')
} );

app.get('/submit', (req, res)=>{

    if (req.isAuthenticated()) {
        res.render("submit");
    }
    else {
        res.redirect("/login");
    }
})
.post('/submit',(req, res)=>{
   const submittedSecret = req.body.secret;
  
   User.findById(req.user.id, (err, foundUser)=>{
    if (err){
        console.log(err)
    } else{
        if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save(()=>{
                res.redirect('/secrets');
            })
        }
    }
   })

})
app.get('/auth/google', 
    passport.authenticate('google', {scope: ['profile']})
  
)

app.get('/auth/google/secrets',

passport.authenticate('google', {failureRedirect: '/login'}),
(req, res)=>{
    res.redirect('/secrets')
}

);

app.get('/auth/facebook', 
    passport.authenticate('facebook')
  
)

app.get('/auth/facebook/secrets',

passport.authenticate('facebook', {failureRedirect: '/login'}),
(req, res)=>{
    res.redirect('/secrets')
}

);


app
.get('/login', (req, res)=>{
    res.render('login')
})


.post("/login",passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
    failureMessage: true,
})


);


app
.get('/register', (req, res)=>{
    res.render('register')
} )

.post('/register', async (req, res)=>{
User.register({username: req.body.username}, req.body.password, (err, user)=>{
    if(err){
        console.log(err)
        res.redirect('/register')
    } else{
        passport.authenticate('local') (req, res, ()=>{
            res.redirect('/secrets')
        })

    }
})
});


app.get("/secrets", (req, res) => {
   
    if (req.isAuthenticated()) {

        User.find({"secret":{$ne: null}}, (err, found)=>{
            if(err){
                console.log(err)
            } else{
                if(found){
                    res.render('secrets', {usersSecrets: found})
                }
            }
        })
    }
    else {
        res.redirect("/login");
    }
});



app.get("/logout", (req,res, next)=>{
    req.logOut((err)=>{
        if(err){ return next(err)}
    });
 
    res.redirect("/");
})



app.listen(Port, ()=>{
    console.log(`Server on on port ${Port}, http://localhost:${Port}`)
});
