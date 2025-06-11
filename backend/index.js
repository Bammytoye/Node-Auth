const express = require('express');
const helmet = require('helmet'); 
const cors = require('cors');

const app = express()

app.use(cors())
app.use(helmet)
app.use(express.json()); //...for req.body

app.get('/', (req, res ) => {
    res.json({message: 'Hello Frontend from Backend'})
})

app.listen(process.env.PORT, () => {
    console.log('Connecting')
})