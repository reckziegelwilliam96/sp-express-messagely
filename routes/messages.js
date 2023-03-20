const express = require("express");
const router = new express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const ExpressError = require("../expressError");
const db = require("../db");
const Message = require("../models/message");
const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require("../config");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get("/:id", ensureLoggedIn, async function (req, res, next) {
    try {
        const { id } = req.params;
        const username = req.user.username;
        const message = Message.get(id);
        if (message.to_user.username !== username && message.from_user.username !== username){
            throw new ExpressError("Cannot read this message", 401)
        }
        return res.json({ msg: message });
    } catch (err){
        return next(err);
    }
})

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post("/", ensureLoggedIn, async function (req, res, next) {
    try {
        const from_username = req.user;
        const { to_username, body} = req.body;
        const message = await Message.create({from_username, to_username, body})
        return res.json({msg: message})
    } catch(err) {
        return next(err)
    }
})

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/:id/read", ensureLoggedIn, async function (req, res, next){
    try {
        const username = req.user.username
        const { id } = req.params;
        const message = await Message.get(id)
        if (message.to_user.username !== username && message.from_user.username !== username){
            throw new ExpressError("Cannot read this message", 401)
        }
        const readMessage = await Message.markRead(id)
        return res.json({readMessage})
    } catch (err){
        return next(err);
    }
})


