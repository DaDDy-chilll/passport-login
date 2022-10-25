const express = require('express');
const passprot = require('passport');
const localStrategy = require('passport-local');
const crypto = require('crypto');
const db = require('../db');
const { route } = require('.');
const router = express.Router();

router.get('/login',(req,res)=>{
    res.render('login');
});

passprot.use(new localStrategy(function verify(username,password,cb){
    db.get('SELECT * FROM users WHERE username=?',[username],function(err,row){
        if(err){return cb(err)}
        if(!row){return cb(null , false,{message:'Incorrect Username and Password'})}
        crypto.pbkdf2(password,row.salt,310000,32,'sha256',function(err,hashedpassword){
            if(err){return cb(err)}
            if(!crypto.timingSafeEqual(row.hashed_password,hashedpassword)){
                return cb(null,false,{message:'Incorrect username and password'})
            }
            return cb(null,row)
        })
    })
}));

passprot.serializeUser(function(user,cb){
    process.nextTick(function(){
        cb(null,{id:user.id,username:user.username})
    })
})

passprot.deserializeUser(function(user,cb){
    process.nextTick(function(){
       return cb(null,user)
    })
})
router.post('/login/password',passprot.authenticate('local',{
    successRedirect:'/',
    failureRedirect:'/login'
}));

router.post('/logout',(req,res,next)=>{
    req.logOut(function(err){
        if(err){return next(err)}
        res.redirect('/')
    })
})

router.get('/signup',(req,res,next)=>{
    res.render('signup');
    next();
})

router.post('/signup',(req,res,next)=>{
    var salt = crypto.randomBytes(16);
    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
      if (err) { return next(err); }
      db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
        req.body.username,
        hashedPassword,
        salt
      ], function(err) {
        if (err) { return next(err); }
        var user = {
          id: this.lastID,
          username: req.body.username
        };
        req.login(user, function(err) {
          if (err) { return next(err); }
          res.redirect('/');
        });
      });
    });
})

module.exports=router;