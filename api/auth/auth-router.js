const router = require('express').Router();
const bcryptjs = require("bcryptjs");
// import the library
const jwt = require('jsonwebtoken');

const Users = require('./auth-users-modal');
const { jwtSecret } = require('./secret.js');



router.post('/register',(req, res) => {
  const credentials = req.body;

  if (isValid(credentials)) {
    const rounds = process.env.BCRYPT_ROUNDS || 8;

    // hash the password
    const hash = bcryptjs.hashSync(credentials.password, rounds);

    credentials.password = hash;

    // save the user to the database
    Users.add(credentials)
      .then(user => {
        const {id, username, password} = user
        res.status(201).json({ id,username,password});
      })
      .catch(error => {
        res.status(500).json('username taken');
      });
  } else {
    res.status(400).json( "username and password required",
    );
  }
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (isValid(req.body)) {
    Users.findBy({ username: username })
      .then(([user]) => {
        if (user && bcryptjs.compareSync(password, user.password)) {
          const token = makeToken(user) // make token
          res.status(200).json({ message: "Welcome to our API", token }); // send it back
        } else {
          res.status(401).json({ message: "Invalid credentials" });
        }
      })
      .catch(error => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      message: "username and password required",
    });
  }
});

function isValid(user) {
  if (!user.username || !user.password) {
    return false
  } else {
    return true
  }
}

function makeToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
  };
  const options = {
    expiresIn: '25 seconds',
  };
  return jwt.sign(payload, jwtSecret, options);
}


module.exports = router;