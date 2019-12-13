const argon2 = require('argon2');
const randomBytes = require('randombytes');
const jwt = require('jsonwebtoken');
const expressJWT = require('express-jwt');

// Fake ORM without database
const User = require('./User');

const secret = process.env.JWT_SECRET;

const register = async ({ email, password }) => {
  const salt = randomBytes(32);
  const hashedPassword = await argon2.hash(password, { salt });

  const user = await User.create({
    email,
    password: hashedPassword,
    salt: salt.toString('hex'),
  });

  // Be careful not to send password or salt
  return {
    email: user.email
  }
}

const login = async ({ email, password }) => {
  const user = await User.findOne({ email });

  if (!user) {
    throw new Error('User not found')
  }

  const isPasswordCorrect = await argon2.verify(user.password, password);
  if (!isPasswordCorrect) {
    throw new Error('Incorrect password')
  }

  const payload = {
    id: user.id,
    email: user.email
  };

  return {
    email: user.email,
    token: jwt.sign(payload, secret, { expiresIn: '6h' }),
  }
}

// Express middleware
const isAuthenticated = expressJWT({
  secret, // Same secret as when we signed
  getToken(req) {
    const { authorization = '' } = req.headers;
    const [type, token] = authorization.split(' ');
    return type === 'Bearer'
      ? token
      : null;
  }
})
// const isAuthenticated = (req, res, next) => {
//   const { authorization = '' } = req.headers;
//   const [type, token] = authorization.split(' ');

//   if (type !== 'Bearer') {
//     res.status(401).send();
//   }

//   try {
//     const user = jwt.verify(token, secret);
//     req.user = user;
//     next();
//   } catch (err) {
//     res.status(401).send();
//   }
// }

module.exports = {
  register,
  login,
  isAuthenticated,
}
