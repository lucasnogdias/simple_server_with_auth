const jwt = require('jwt-simple');
const config = require('../config');
const User = require('../models/user');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next){
  // User has already had their email and password auth'd
  // We just need to give them a token
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const {email, password} = {...req.body};

  if (!email || !password) { 
    return res.status(422).send({ error: 'You must provide email and password'});
  }

  // See if user with given email exists
  User.findOne({ email: email }, (err, existingUser) => {
    if (err) { return next(err); }

    // If a user with email does exist, return an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email already in use' });
    }

    // If no user with this email exists, create and save user record
    const user = new User({
      email: email,
      password: password,
    });

    user.save( err => {
      if (err) { return next(err); }

      //Respond to request indicating the user was created
      res.json( { token: tokenForUser(user) });
    });
  });
}