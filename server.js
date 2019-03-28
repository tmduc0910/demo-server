const fs = require('fs')
const bodyParser = require('body-parser')
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')

const server = jsonServer.create()
const router = jsonServer.router('./db.json')
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8'))

server.use(jsonServer.defaults())
server.use(bodyParser.urlencoded({extended: true}))
server.use(bodyParser.json())

const SECRET_KEY = '12345678'
const expiresIn = '1h'

//Create a token from a payload
function createToken(payLoad) {
    return jwt.sign(payLoad, SECRET_KEY, {expiresIn})
}

//Verify the token
function verifyToken(token) {
    return jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ? decode : err)
}

//Check if the user exist in database
function isAuthenticated({username, password}) {
    return userdb.users.findIndex(user => user.username === username && user.password === password) !== -1 
}

server.post('/auth/login', (req, res) => {
    const {username, password} = req.body
    if (isAuthenticated({username, password}) === false) {
        const status = 401
        const message = 'Incorrect username or password'
        res.status(status).json({status, message})
        return
    }

    const access_token = createToken({username, password})
    let user = userdb.users[userdb.users.findIndex(user => user.username === username && user.password === password)]
    res.status(201).json({ username: user.username, password: user.password, name: user.name, email: user.email, gender: user.gender, phone: user.phone });
})

server.use(/^(?!\/auth).*$/,  (req, res, next) => {
    if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
        const status = 401
        const message = 'Bad authorization header'
        res.status(status).json({status, message})
        return
    }
    try {
        verifyToken(req.headers.authorization.split(' ')[1])
        next()
    } catch (err) {
        const status = 401
        const message = 'Error: access_token is not valid'
        res.status(status).json({status, message})
    }
  })

server.use(router)
server.listen(3000, () => {
    console.log('Run Auth API Server')
})

