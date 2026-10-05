const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const Joi = require("joi")
require('dotenv').config()

const port = 3000
const app = express()

app.use(express.json())
app.use(cors())

mongoose.connect("mongodb://localhost:27017/Practice_2").then(() =>
    console.log("MongoDB Connected")).catch((error) => console.error("Error connecting MongoDB:", error))

const userSchema = new mongoose.Schema({
    name: {
        type: String
    },
    email: {
        type: String
    },
    password: {
        type: String
    },
    role: {
        type: String,
        enum: ["user", "admin"],
        default: "user"
    }
})

const User = mongoose.model("User", userSchema)

//userSchema Validation
const userSchemaValidation = Joi.object({
    name: Joi.string().required(),
    email: Joi.string()
        .email({ tlds: { allow: false } })
        .required()
        .messages({
            'string.empty': 'Email is required',
            'string.email': 'enter a valid email address',
            'any.required': 'Email is required'
        }),
    password: Joi.string().min(6).required().messages({
        'string.empty': 'Password is required',
        'string.min': 'Password must be a atleast 6 characters',
        'any.required': 'Password is a must'
    }),
    role: Joi.string().required()
})

//login schema Validation
const loginSchemaValidation = Joi.object({
    email: Joi.string()
        .email({ tlds: { allow: false } })
        .required()
        .messages({
            'string.empty': 'Email is required',
            'string.email': 'enter a valid email address',
            'any.required': 'Email is required'
        }),
    password: Joi.string().min(6).required().messages({
        'string.empty': 'Password is required',
        'string.min': 'Password must be a atleast 6 characters',
        'any.required': 'Password is a must'
    })
})

const sanitizeUser = (userDoc) => {
    const user = userDoc.toObject ? userDoc.toObject() : { ...userDoc }
    delete user.password
    return user
}

//authMiddleware
const authMiddleware = async (req, res, next) => {
    try {
        const header = req.headers.authorization
        const token = header?.split(" ")[1]
        if (!token) {
            return res.status(403).json({ message: "token is requiered" })
        }
        const decodeToken = jwt.verify(token, process.env.JWT_SECRET)
        const user = await User.findById(decodeToken.userId)
        if (!user) {
            return res.status(401).json({ message: "Unauthorized request" })
        }
        req.user = user
        next()
    } catch (error) {
        console.error("Error authorizing:", error)
        return res.status(403).json({ message: "Invalid or expired token" })
    }
}

const authorizeRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: "You are not allowed to access this role" })
        }
        next()
    }
}

app.post("/register", async (req, res) => {
    try {
        const { error } = userSchemaValidation.validate(req.body)
        if (error) {
            return res.status(403).json({
                message: error.details[0].message
            })
        }
        const existingUser = await User.findOne({ email: req.body.email })
        if (existingUser) {
            return res.status(401).json({ message: "User alredy existed" })
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        const newUser = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
            role: "user"
        })
        await newUser.save()
        const token = jwt.sign({
            userId: newUser._id,
            email: newUser.email,
            role: newUser.role
        }, process.env.JWT_SECRET)
        res.status(201).json({ user: sanitizeUser(newUser), token, message: "User registred Successfully" })
    } catch (error) {
        console.error("Error creating the register")
        res.status(500).json({ message: "Internal server" })
    }
})

app.post("/login", async (req, res) => {
    try {
        const { error } = loginSchemaValidation.validate(req.body)
        if (error) {
            return res.status(403).json({
                message: error.details[0].message
            })
        }
        const user = await User.findOne({ email: req.body.email })
        if (!user) {
            return res.status(402).json({ message: "Invalid email or password" })
        }
        const isPassword = await bcrypt.compare(req.body.password, user.password)
        if (!isPassword) {
            return res.status(401).json({ message: "Invalid Emial or password" })
        }
        const token = jwt.sign({
            userId: user._id,
            email: user.email,
            role: user.role
        }, process.env.JWT_SECRET)
        res.status(201).json({ user: sanitizeUser(user), token, message: "Login Successful" })
    } catch (error) {
        console.error("Error while logining:", error)
        res.status(500).json({ message: "Internal server error" })

    }
})

app.get("/userdetailes", authMiddleware, async (req, res) => {
    try {
        const { id } = req.params
        const user = await User.find().select("-password")
        res.status(200).json({ user, message: "Users fetched successfully" })
    } catch (error) {
        console.error("Error fetching the users:", error)
        res.status(500).json({ message: "Internal server error" })
    }
})

app.get("/usergetid/:id", authMiddleware, async (req, res) => {
    try {
        const { id } = req.params
        const user = await User.findById(id).select("-password")
        res.status(200).json({ user, message: "User fetched successfully" })
    } catch (error) {
        console.error("Error fetching the user:", error)
        res.status(500).json({ message: "Internal server error" })
    }
})

app.put("/editinguser/:id", authMiddleware, authorizeRole("user"), async (req, res) => {
    try {
        const { id } = req.params
        if (req.user._id.toString() !== req.params.id) {
            return res.status(403).json({
                message: "You can only edit your own account"
            })
        }
        const hashPassword = await bcrypt.hash(req.body.password, 10)
        const user = await User.findByIdAndUpdate(id, {
            name: req.body.name,
            email: req.body.email,
            password: hashPassword,
        })
        await user.save()
        res.status(201).json({ user, message: "User updated successfully" })
    } catch (error) {
        console.error("Error editing user:", error)
        res.status(500).json({ message: "Internal server error" })
    }
})

app.delete("/deletinguser/:id", authMiddleware, authorizeRole("user"), async (req, res) => {
    try {
        const { id } = req.params
        const user = await User.findByIdAndDelete(id)
        res.status(200).json({ user, message: "User deleted successfully" })
    } catch (error) {
        console.error("Error deleting user:", error)
        res.status(500).json({ message: "Internal server error" })
    }
})

app.listen(port, () => {
    console.log(`Server is running on the http://localhost:${port}`)
})