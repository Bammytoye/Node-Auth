const express = require('express')

const app = express()

app.use(express.json()); //...for req.body

app.get('/', (req, res ) => {
    res.json({message: 'Hello Frontend from Backend'})
})

app.listen(process.env.PORT, () => {
    console.log('Connecting')
})