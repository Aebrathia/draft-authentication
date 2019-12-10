const express = require('express');
const app = express();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const user = {
  username: 'admin',
  password: 'password'
}

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  return res.redirect('/login');
}

passport.serializeUser((user, done) => done(null, user.username));
passport.deserializeUser((username, done) => done(err, { username: user.username }));
passport.use(new LocalStrategy((username, password, done) => {
  console.log({ username, password })
  if (username !== user.username) {
    return done(null, false, { message: 'Incorrect username.' });
  }
  if (password !== user.password) {
    return done(null, false, { message: 'Incorrect password.' });
  }
  return done(null, { username: user.username });
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.get('/users/:username', isLoggedIn, (req, res) => {
  res.send(req.user.username);
});

app.get('/login', (req, res) => {
  res.send(`
    <form action="/login" method="post">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" />
      <button type="submit">Submit</submit>
    </form>
  `);
});

app.post(
  '/login',
  passport.authenticate('local', {
    failureRedirect: '/login',
  }),
  (req, res) => {
    res.redirect('/users/' + req.user.username);
  }
);

app.listen(3000, () => {
  console.log('Listening on port 3000');
})
