require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();
const { SERVER_PORT, CONNECTION_STRING, SECRET } = process.env;

app.use(express.json());
app.use(session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false
}))


massive(CONNECTION_STRING).then(db => app.set('db', db));

app.get('db')

app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  const db = app.get('db')
  let user = await db.find_user({ email: email });
  if (user.length === 0) {
    const salt = bcrypt.genSaltSync(10)
    const hash = bcrypt.hashSync(password, salt)
    const createdUser = await db.create_cust({ email: email, hash_value: hash })
    req.session.user = { id: createdUser[0].cust_id, email: createdUser[0].email };
    res.status(200).send({ message: 'Logged in', userData: req.session.user })
  } else {
    return res.status(200).send({ message: 'Email already in use.' })
  }
})

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const db = app.get('db');
  const user = await db.find_user({ email: email });
  if (user.length === 0) {
    res.status(200).send({ message: 'Email not found' })
  } else {
    const result = bcrypt.compareSync(password, user[0].hash_value)
    if (result === true) {
      req.session.user = { id: user[0].cust_id, email: user[0].email }
      return res.status(200).send({ message: 'logged in', userData: req.session.user });
    } else {
      return res.status(401).send({ message: 'wrong password' })
    }
  }
})

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.status(200).send('Logged out')
})

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`)
})

