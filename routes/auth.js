const express = require("express");
const router = new express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const ExpressError = require("../expressError");
const db = require("../db");
const User = require("../models/user");
const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require("../config");


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async function(req, res, next){
    try {
        const { username, password} = req.body;
        const user = User.authenticate(username, password);
        if (user){
            if (await bcrypt.compare(password, user.password) === true){
                User.updateLoginTimestamp(username)
                let token = jwt.sign({ username }, SECRET_KEY)
                return res.json({ token })
            }
        }
        throw new ExpressError("Invalid user/password", 400)
    } catch(err){
        return next(err)
    }
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

 router.post("/register", async function(req, res, next){
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
        User.register(username, hashedPassword, first_name, last_name, phone);
        let token = jwt.sign({username}, SECRET_KEY)
        return res.json({ token })
    } catch(err){
        return next(err)
    }
})


