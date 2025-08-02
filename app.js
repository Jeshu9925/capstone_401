import express from 'express';
import bcryptjs from 'bcryptjs';
import bodyParser from 'body-parser';
import admin from 'firebase-admin';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const serviceAccount = JSON.parse(
  fs.readFileSync('./serviceAccountKey.json', 'utf8'));
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;

// Firebase Admin SDK Initialization
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const usersRef = db.collection('users');

// Middleware
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Routes

app.get('/', (req, res) => res.redirect('/login'));

// Signup
app.get('/signup', (req, res) => {
  res.render('signup', { message: null });
});

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  const snapshot = await usersRef.where('email', '==', email).get();
  if (!snapshot.empty) {
    return res.render('signup', { message: 'Email already exists' });
  }

  const hashedPassword = await bcryptjs.hash(password, 10);
  try {
    await admin.auth().createUser({
      email,
      password,
      displayName: name
    });
  } catch (error) {
    return res.render('signup', { message: error.message });
  }
  await usersRef.add({
    name,
    email,
    password: hashedPassword
  });

  res.redirect('/login');
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { message: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const snapshot = await usersRef.where('email', '==', email).get();
  if (snapshot.empty) {
    return res.render('login', { message: 'User not found' });
  }

  const userDoc = snapshot.docs[0];
  const user = userDoc.data();

  const isMatch = await bcryptjs.compare(password, user.password);
  if (!isMatch) {
    return res.render('login', { message: 'Incorrect password' });
  }

  res.redirect(`/dashboard?name=${user.name}`);
});

// Dashboard
app.get('/dashboard', (req, res) => {
  const name = req.query.name;
  res.render('dashboard', { name });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
