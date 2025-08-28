const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
require('dotenv').config();

// Routes
const authRouter = require('./routes/authRouter.js');

const app = express();

// ===== Middlewares =====
app.use(cors());
app.use(helmet());
app.use(cookieParser());
app.use(express.json()); // Parse JSON body
app.use(express.urlencoded({ extended: true })); // Parse form-urlencoded body

// ===== Routes =====
app.use('/api/v1/auth', authRouter);

app.get('/', (req, res) => {
    res.json({ message: 'Hello Frontend from Backend' });
});

// ===== Database Connection =====
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Database Connected'))
    .catch((err) => console.error('❌ DB Connection Error:', err));

// ===== Start Server =====
const PORT = process.env.PORT || 2000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
