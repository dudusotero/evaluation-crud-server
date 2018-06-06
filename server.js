const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const server = jsonServer.create();

const router = jsonServer.router('./database.json');
const userdb = JSON.parse(fs.readFileSync('./db.json', 'UTF-8'));

const corsOptions = {
  "origin": "*",
  "methods": "GET,HEAD,PUT,PATCH,POST,DELETE",
  "preflightContinue": false,
  "optionsSuccessStatus": 204,
  "exposedHeaders": ['Authorization']
};

server.use(cors(corsOptions));
// server.use(jsonServer.defaults());
server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());

const SECRET_KEY = '123456789';

const expiresIn = '1h';

function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ? decode : err);
}

function isAuthenticated({ email, password }) {
  return userdb.users.findIndex(user => user.email === email && user.password === password) !== -1;
}

server.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (isAuthenticated({ email, password }) === false) {
    const status = 401;
    const message = 'Incorrect email or password';
    res.status(status).json({ status, message });
    return;
  }
  const access_token = createToken({ email, password });
  const user = userdb.users.find(user => user.email === email && user.password === password);
  res.status(200).json({ access_token, user });
});

server.get('/users', (req, res) => {
  const data = userdb.users;
  res.status(200).json({ data });
});

server.get('/users/:id', (req, res) => {
  const data = userdb.users.find(user => user.id == req.params.id);
  res.status(200).json({ data });
});

server.post('/users', (req, res) => {
  userdb.users.push(req.body);
  const data = userdb.users;
  res.status(200).json({ data });
});

server.put('/users/:id', (req, res) => {
  const index = userdb.users.findIndex(user => user.id == req.params.id);
  userdb.users[index] = req.body;
  console.log(userdb.users);
  const data = userdb.users;
  res.status(200).json({ data });
});

server.delete('/users/:id', (req, res) => {
  const index = userdb.users.findIndex(user => user.id == req.params.id);
  const data = userdb.users.splice(index, 1);
  res.status(200).json({ data });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  console.log(req.headers.authorization);
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401;
    const message = 'Error in authorization format';
    res.status(status).json({ status, message });
    return;
  }
  try {
    verifyToken(req.headers.authorization.split(' ')[1]);
    next();
  } catch (err) {
    const status = 401;
    const message = 'Error access_token is revoked';
    res.status(status).json({ status, message });
  }
});

server.use(router);

server.listen(3000, () => {
  console.log('Run Auth API Server');
});