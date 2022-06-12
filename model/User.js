const mongoose = require('mongoose') 

//Creation of an collection in mongoDB

const User = mongoose.model('User', {
    name: String, 
    email: String, 
    password: String
})

module.exports = User;  