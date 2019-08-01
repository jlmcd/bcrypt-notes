require('dotenv').config()
const express = require('express')
const session = require('express-session')
const bcrypt = require('bcryptjs')
const massive = require('massive')
const { SERVER_PORT, CONNECTION_STRING, SECRET } = process.env

const app = express()

app.use(express.json())
app.use(session({
    secret: SECRET,
    resave: false,
    saveUninitialized: false
}))

massive(CONNECTION_STRING).then(db => app.set('db', db))

app.post('/api/signup', async (req, res) => {
    /*
    1. check to see if email already exists in database
        a. if so, send proper response
    2. hash and salt password, and create new user in db
    3. put new user on session
    4. respond with user info 
    */
    const { email, password } = req.body
    const db = app.get('db')
    let user = await db.find_user({ email })
    if (user.length === 0) {
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        const createdUser = await db.create_cust({ email, hash_value: hash })
        // put user on session
        req.session.user = { id: createdUser[0].cust_id, email: createdUser[0].email }
        res.status(200).send({ message: 'Logged in', userData: req.session.user })

    } else {
        return res.status(200).send({ message: 'Email already in use' })
    }
})

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body
    const db = app.get('db')
    const user = await db.find_user({ email })
    if (user.length === 0) {
        res.status(200).send({ message: 'Email not found' })
    } else {
        const result = bcrypt.compareSync(password, user[0].hash_value)
        if (result === true) {
            req.session.user = { id: user[0].cust_id, email: user[0].email }
            return res.status(200).send({ message: 'logged in', userData: req.session.user })
        } else {
            return res.status(401).send({ message: 'wrong password' })
        }
    }
})

app.get('/api/logout', (req, res) => {
    req.session.destroy()
    res.status(200).send({ message: 'logged out' })
})

app.listen(SERVER_PORT, () => {
    console.log(`Listening on port ${SERVER_PORT}`)
})