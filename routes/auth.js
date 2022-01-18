const express = require('express');
const ExpressError = require('../expressError');
const router = new express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { updateLoginTimestamp } = require('../models/user');
const { SECRET_KEY } = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
 router.post('/login', async function(req, res, next) {
     try {
        const { username, password } = req.body;

        if (await User.authenticate(username, password)) {
            let user = await User.get(username);
            await updateLoginTimestamp(username);
            let token = jwt.sign( {username:user.username}, SECRET_KEY);
            return res.json( {token});
        }
        throw new ExpressError('Invalid username and/or password', 400);
     } catch (err) {
        return next(err);
     }
 });


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post('/register', async function(req, res, next) {
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        if (!username || !password || !first_name || !last_name || !phone) {
            throw new ExpressError('Username, password, first name, last name and phone required.', 400);
        }
        // add user to db
        const user = await User.register({username, password, first_name, last_name, phone});

        // log user in
        let token = jwt.sign( {username:user.username}, SECRET_KEY);
        await updateLoginTimestamp(user.username);
        return res.json( {token} );
    } catch (err) {
        return next(err);
    }
})

module.exports = router;
