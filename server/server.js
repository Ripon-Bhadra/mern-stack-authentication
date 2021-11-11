const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/user');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));

mongoose.connect("mongodb://localhost:27017/testbd", {useNewUrlParser: 'true', })

mongoose.connection.on("error", err => {
    console.log("err", err)
})

mongoose.connection.on("connected", (err, res) => {
    console.log("mongoose is connected...")
})

app.post('/register', async(req, res) => {
    const user = req.body;

    const takeName = await User.findOne({username: user.username})
    const takeEmail = await User.findOne({email: user.email})

    if(takeName || takeEmail) {
        res.json({message: "Username or email has already been taken"})
    } else {
        user.password = await bcrypt.hash(req.body.password, 10)

        const dbUser = new User({
            username: user.username.toLowerCase(),
            email: user.email.toLowerCase(),
            password: user.password
        })

        dbUser.save()
        res.json({message: "Success"})
    }
})

app.post('/login', (req, res) => {
    const userLoggingIn = req.body;

    User.findOne({username: userLoggingIn.username})
    .then(dbUser => {
        if(!dbUser) {
            return res.json({
                message: "Invalid Username or password"
            })
        }
        bcrypt.compare(userLoggingIn.password, dbUser.password)
        .then(isCorrect => {
            if(isCorrect) {
                const payload = {
                    id: dbUser._id,
                    username: dbUser.username,
                }

                jwt.sign(
                    payload,
                    process.env.JWT_SECRET,
                    {expiresIn: 86400},
                    (err, token) => {
                        if(err) return res.json({message:err})
                        return res.json({
                            message:"Success",
                            token: "Bearer " + token
                        })
                    }
                )

            } else {
                return res.json({
                    message: "Invaild Username or password"
                })
            }
        })
    })
})


app.get('/getUsername', verifyJWT, (req, res) => {
    res.json({isLoggedIn: true, username: req.body.username})
})

function verifyJWT(req, res, next) {
    const token = req.headers["x-access-token"]?.split(' ')[1]

    if(token) {
        jwt.verify(token, process.env.PASSPORTSECRET, (err, jwt.decode) => {
            if(err) return res.json({
                isLoggedIn: false,
                message: "Failed To Authenticate"
            })
            req.user = {};
            req.user.id = decode.id
            req.user.username = decode.username
            next()
        }) 
    } else {
        res.json({
            message: "Incorrect Token Given", isLoggedIn: false
        })
    }
}

app.listen(4000, () => {
    console.log('Server is running on localhost 4000')
});