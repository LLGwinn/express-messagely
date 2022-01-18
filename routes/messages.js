const express = require('express');
const ExpressError = require('../expressError');
const router = new express.Router();
const jwt = require('jsonwebtoken');
const Message = require('../models/message');
const { updateLoginTimestamp } = require('../models/user');
const e = require('express');
const {ensureLoggedIn, ensureCorrectUser} = require('../middleware/auth');

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

router.get('/:id', ensureLoggedIn, async function(req, res, next) {
    try {
        const message = await Message.get(req.params.id);

        if (message.from_user.username !== req.user.username ||
            message.to_user.username !== req.user.username) {
                throw new ExpressError("Not authorized to view this message.", 401);
            }
        else {
            return message;
        }

    } catch(err) {
        return next(err);
    }
})


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post('/', ensureLoggedIn, async function(req, res, next) {
    try {
        const from = req.user.username;
        const to = req.body.to_username;
        const body = req.body.body;
        const message = await Message.create(
            {from_username:from, to_username:to, body:body}
        );
        return res.json({message});
    } catch(err) {
        return next(err);
    }
} )


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
router.post('/:id/read', ensureLoggedIn, async function(req, res, next) {
    try {
        const messageData = await Message.get(+req.params.id);

        if (req.user.username === messageData.to_user.username) {
            const message = await Message.markRead(+req.params.id);
            return res.json({message});
        }
        else {
            throw new ExpressError("Must be message recipient to view this message", 401);
        }
    } catch(err) {
        return next(err);
    }
})

module.exports = router;

