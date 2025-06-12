const express = require('express');
const helmet = require('helmet'); 
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose')
require('dotenv').config();

const authRouter = require('./routes/authRouter.js') 

const app = express()

app.use(cors())
app.use(helmet())
app.use(cookieParser());
app.use(express.json()); //...for req.body
app.use(express.urlencoded({extended: true}))

app.use('/api/v1/auth', authRouter)

mongoose.connect(process.env.MONGO_URI).then(() => {
    console.log('Database Connected')
}).catch ((err) => {
    console.log(err)
})

app.get('/', (req, res ) => {
    res.json({message: 'Hello Frontend from Backend'})
})

app.listen(process.env.PORT, () => {
    console.log('Connecting')
})