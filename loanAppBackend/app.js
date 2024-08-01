const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

mongoose.connect('mongodb://localhost/loan-app', { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
    fullName: String,
    email: String,
    password: String
});

const loanSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    amount: Number,
    purpose: String,
    term: String
});

const User = mongoose.model('users', userSchema);
const Loan = mongoose.model('loans', loanSchema);

const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
    if (!token) return res.status(401).send('Access denied.');

    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err) return res.status(403).send('Invalid token.');
        req.userId = decoded.userId;
        next();
    });
};

app.post('/signup', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        if (!fullName || !email || !password) {
            return res.status(400).send('All fields are required');
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = new User({
            fullName,
            email,
            password: hashedPassword
        });

        await newUser.save();
        res.status(201).send('User created successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.post('/signin', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('User not found');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send('Invalid password');

    const token = jwt.sign({ userId: user._id }, 'secret_key');
    res.send({ token });
});

app.post('/apply-loan', authenticateToken, async (req, res) => {
    try {
        const { amount, purpose, term } = req.body;
        const loan = new Loan({
            userId: req.userId,
            amount,
            purpose,
            term,
        });
        await loan.save();
        res.status(201).send('Loan applied successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.get('/loans', authenticateToken, async (req, res) => {
    try {
        const loans = await Loan.find({ userId: req.userId });
        res.send(loans);
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.get('/loans', async (req, res) => {
    const loans = await Loan.find();
    res.send(loans);
});

app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
      console.error('Bad JSON');
      return res.status(400).send({ error: 'Invalid JSON' });
    }
    next();
  });
  

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
