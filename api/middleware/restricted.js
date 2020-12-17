
const jwt = require('jsonwebtoken')
const { jwtSecret } = require('../auth/secret')

module.exports = (req, res, next) => {

  const token = req.headers.authorization

  if (!token) {
    return res.status(401).json({ message: 'we wants token' })
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      console.log('decoded error ->', err)
      return res.status(401).json({ message: 'token bad' })
    }

    console.log('decoded token ->', decoded)
    req.decodedJwt = decoded
    next()
  })
}