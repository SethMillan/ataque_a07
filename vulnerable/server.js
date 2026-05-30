const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});


app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const users = [
  { id: 1, username: 'admin', password: 'admin123' },
  { id: 2, username: 'user', password: 'user123' }
];

 app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: false
}));

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (user) {
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ success: true, message: 'Login exitoso' });
  } else {
    res.json({ success: false, message: 'Credenciales incorrectas' });
  }
});


app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'No autenticado' })
  }
  res.json({ message: 'Bienvenido ' + req.session.username })
})