const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// PostgreSQL connection
const pool = new Pool({
  user: 'neondb_owner',
  host: 'ep-odd-truth-a18bckkw-pooler.ap-southeast-1.aws.neon.tech',
  database: 'neondb',
  password: 'npg_uT0EgnSc9UQB',
  port: 5432,
  ssl: true,
});

// Middleware to parse JSON
app.use(express.json());
app.use(cors());

// Secret key for JWT
const JWT_SECRET = 'your_jwt_secret_key';

// Helper function to generate JWT
const generateToken = (user) => {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: '1h', // Token expires in 1 hour
  });
};

app.get('/hello',(req,res)=>{
    res.send("bro");
})
// Register endpoint
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING *',
      [username, hashedPassword, email]
    );
    const user = result.rows[0];
    const token = generateToken(user);
    res.json({ user, token });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    // Generate JWT
    const token = generateToken(user);
    res.json({ user, token });
  } catch (err) {
    console.error('Error logging in:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Protected endpoint example
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

// Middleware to authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});