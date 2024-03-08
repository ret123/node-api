const User = require('../models/User')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')


const login = asyncHandler(async (req,res) => {
    const {username,password} = req.body

    if(!username || !password) {
        return res.status(400).json({message: 'All fields are required'})
    }

    const user = await User.findOne({username}).exec()

    if(!user || !user.active) {
        return res.status(401).json({message: 'Unauthorized'})
    }

    const match = await bcrypt.compare(password,user.password)
    if(!match) {
        console.log('inside match error')
        return res.status(401).json({message: 'Unauthorized'})
    }

    const accessToken = jwt.sign(
        {
            "UserInfo": {
                "username": user.username,
                "roles": user.roles
            }
        },
        process.env.ACCESS_TOKEN_SECRET,
        {expiresIn: '15m'}
    )

    const refreshToken = jwt.sign(
        {
            "username": user.username
        },
        process.env.REFRESH_TOKEN_SECRET,
        {expiresIn: '7d'}
    )

    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    res.json({accessToken})
}) 

const refresh = asyncHandler(async (req,res) => {
    const cookies = req.cookies

    if(!cookies?.jwt) return res.status(401).json({message: 'Unauthorized'})
    const refreshToken = cookies.jwt

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        asyncHandler(async(err,decoded) => {
            if(err) return res.status(403).json({message: 'Forbidden'})

            const user = await User.findOne({username: decoded.username}).exec()

            if(!user) return res.status(401).json({message: 'Unauthorized'})

            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": user.username,
                        "roles": user.roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                {expiresIn: '15m'}
            )
            res.json({accessToken})
        })
    )
}) 

const logout = asyncHandler(async (req,res) => {
    const cookies = req.cookies
    if(!cookies?.jwt) return res.sendStatus(204)
    res.clearCookie('jwt',{httpOnly: true, sameSite: 'None', secure: true})
    res.json({message: 'Cookie cleared'})
}) 

module.exports = {
    login,
    refresh,
    logout
}