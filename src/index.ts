import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';

import jwt from 'jsonwebtoken';
import passport from 'passport';
import * as passportjwt from 'passport-jwt';

import { Strategy as JwtStrategy, ExtractJwt as ExtractJwt } from 'passport-jwt';

import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import {Strategy as FacebookStrategy } from 'passport-facebook';

const DATA = [ // should be a database or something persistant
  {email:"test@gmail.com", password:"1234"}, // user data from email-password
  {email:"test2@gmail.com", provider:"facebook"} // user data from OAuth has no password
];

const app = express();

// Config
const config = { secretOrKey:"mysecret" }

// Middlewares
app.use(bodyParser.urlencoded({ extended: false })) 
app.use(cookieParser())
app.use(passport.initialize()); 

// Utility functions for checking if a user exists in the DATA array - Note: DATA array is flushed after every restart of server
function FindOrCreate(user){
    if(CheckUser(user)){  // if user exists then return user
        return user;
    }else{
        DATA.push(user); // else create a new user
    }
}
function CheckUser(input){
    for (var i in DATA) {
        if(input.email==DATA[i].email && (input.password==DATA[i].password || DATA[i].provider==input.provider))
            return true; // found
        else
            null; //console.log('no match')
      }
    return false; // not found
}

var opts = {};

opts.jwtFromRequest = function(req) { // tell passport to read JWT from cookies
    var token = null;
    if (req && req.cookies){
        token = req.cookies['jwt']
    }
    return token;

}
opts.secretOrKey = config.secretOrKey;

// main authentication, our app will rely on it
passport.use(new JwtStrategy(opts, function(jwt_payload, done) {
    console.log("JWT BASED AUTH GETTING CALLED") // called everytime a protected URL is being served
    if (CheckUser(jwt_payload.data)) {
        return done(null, jwt_payload.data);
    } else {
        // user account doesnt exists in the DATA
        return done(null, false);
    }
}))

passport.use(new GoogleStrategy({
    clientID: "1038574997890-0mpugpgh22cb956t160seko9cn4uo41c.apps.googleusercontent.com",
    clientSecret: "NROxRNWUxJZmkar_YNYa--Fu",
    callbackURL: "http://localhost:5000/googleRedirect"
  },
  function(accessToken, refreshToken, profile, done) {
      //console.log(accessToken, refreshToken, profile)
      console.log("GOOGLE BASED OAUTH VALIDATION GETTING CALLED")
      return done(null, profile)
  }
))

passport.use(new FacebookStrategy({
    clientID: '378915159425595',//process.env['FACEBOOK_CLIENT_ID'],
    clientSecret: '7bd791932eaf12fbb75d0166721c0e02',//process.env['FACEBOOK_CLIENT_SECRET'],
    callbackURL: "http://localhost:5000/facebookRedirect", // relative or absolute path
    profileFields: ['id', 'displayName', 'email', 'picture']
  },
  function(accessToken, refreshToken, profile, done) {
    console.log(profile)
    console.log("FACEBOOK BASED OAUTH VALIDATION GETTING CALLED")
    return done(null, profile)
  }))
  
// These functions are required for getting data To/from JSON returned from Providers
passport.serializeUser(function(user, done) {
    console.log('I should have jack ');
    done(null, user);
})
passport.deserializeUser(function(obj, done) {
    console.log('I wont have jack shit');
    done(null, obj);
})