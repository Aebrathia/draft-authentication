require('dotenv').config();
const express = require('express');
const auth = require('./auth');
const User = require('./User');

const app = express();

app.use(express.urlencoded());
app.use(express.json());

app.get('/api/v1/users', auth.isAuthenticated, async (req, res) => {
  const users = await User.findAll();
  res.send(users);
});

app.post('/api/v1/users', async (req, res) => {
  const { email, password } = req.body;
  const user = await auth.register({ email, password });
  res.send(user);
});

app.post('/api/v1/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { token } = await auth.login({ email, password });
    res.send({ token });
  } catch (err) {
    res.status(401).send();
  }
});

app.listen(3000, () => {
  console.log('Listening on port 3000');
})
