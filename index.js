const express = require('express');
const app = express();
const passport = require('passport');
const { Strategy, ExtractJwt } = require('passport-jwt');
const jwt = require('jsonwebtoken');

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: '6}DqgeWHhGnj}-3jw$K&`(_N*e(x4V#N#,gE17A|oK$Bl?Y<J~e:`M[r6&Mt/3$',
  // issuer: 'sso.wildcodeschool.fr', // Which service created the token
  // audience: 'www.wildcodeschool.fr', // Which service is the token intended for
}

const users = [{
  id: 1,
  email: 'john.smith@email.com',
  password: 'password',
}, {
  id: 2,
  email: 'foo.bar@email.com',
  password: 'password2',
}];

passport.use(new Strategy(jwtOptions, (jwtPayload, done) => {
  const user = users.find(u => u.id === jwtPayload.id);

  if (user) {
    const { password, ...userWithoutPassword } = user;
    return done(null, userWithoutPassword);
  }

  return done(null, false);
}));

app.use(passport.initialize());
app.use(express.urlencoded());
app.use(express.json());

app.get('/api/v1/users', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.send(req.user);
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(401).send();
  }

  if (user.password !== password) {
    return res.status(401).send();
  }

  const payload = { id: user.id };
  const token = jwt.sign(payload, jwtOptions.secretOrKey);
  res.send({ token });
});

app.listen(3000, () => {
  console.log('Listening on port 3000');
})
