require('dotenv').config()
const express = require('express')
const mongoose = require ('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')


const app = express()

//config JSON response
app.use(express.json())


//Models
const User = require('./model/User')

//open route / public route 
app.get('/', (req, res) =>{
    res.status(200).json({message: 'Bem vindo a nossa API'})
})

//private route
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id
    
    //check if user exists
    const user = await User.findById(id, '-password')
    res.status(200).json({user})
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]
    if(!token){
        return res.status(401).json({msg: 'Acesso negado'})
    }
    try {
        
        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()


    } catch (error) {
        return res.status(400).json({msg: 'Token inválido!'})
    }
}

app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmPassword} = req.body
    //validations
    if(!name){
        return res.status(422).json({ message: 'Nome não encontrado'})
    }
    if(!email){
        return res.status(422).json({ message: 'Email não encontrado'})
    }
    if(!password){
        return res.status(422).json({ message: 'Password não encontrado'})
    }
    if(password !== confirmPassword){
        return res.status(422).json({ message: 'Senhas não conferem!'})
    }
    const UserExists = await User.findOne({ email: email})
    if(UserExists){
        return res.status(422).json({ message: 'Por gentileza, insira outro email!'})
    }
    const salt = await bcrypt.genSalt()
    const passwordHash = await bcrypt.hash(password, salt)

    // create user

    const user = new User({
        name, 
        email, 
        password: passwordHash
    })
    try {
        await user.save()
        res.status(201).json({message: 'Usuário salvo com sucesso!!'})
    } catch (error) {

        console.log(error)
        res.status(500).json({message: 'Aconteceu um erro no servidor, tente novamente mais tarde!!'})
    }
})

//Login User

app.post('/auth/login', async(req, res) => {
    const { email, password} = req.body
    if(!email){
        return res.status(422).json({ message: 'Email não encontrado'})
    }
    if(!password){
        return res.status(422).json({ message: 'Password não encontrado'})
    }
    //check if user exists
    const findUser = await User.findOne({ email: email})
    if(!findUser){
        return res.status(404).json({ message: 'Usuário não encontrado!'})
    }
    //check if password match
    const checkedPassword = await bcrypt.compare(password, findUser.password)
    if(!checkedPassword){
        return res.status(422).json({ message: 'Senha incorreta! Tente novamente!'})
    }
    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: findUser._id,
        }, secret)

        res.status(200).json({ message: 'Autenticação realizada com sucesso', token})
    } catch (error) {
        console.log(error)
        res.status(500).json({message: 'Aconteceu um erro no servidor, tente novamente mais tarde!!'})
    }
})

//CREDENTIALS

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.kqt87.mongodb.net/?retryWrites=true&w=majority`).then(() => {
app.listen(3000)
console.log('Entrada no banco de dados com sucesso!')
}).catch((err) => {
    console.log(err)
})
