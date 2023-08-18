const { Router } = require('express')
const ExpressError = require('../expressError')
const router = new Router()
const Message = require('../models/message')
const {ensureLoggedIn, ensureCorrectUser} = require('../middleware/auth')

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

router.get('/:id', ensureLoggedIn, async function(req,res,next){
    try{
        let username = req.user.username;
        let id = req.params.id
        let message = await Message.get(id)
        if(username !== message.to_user.username && username !== message.from_user.username){
            throw new ExpressError(`Error: you do not have access to this message`,401)
        }
        else{
            return res.json({message : message})
        }
    }
    catch(err){
        return next(err)
    }
})


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post('/', ensureLoggedIn, async function(req,res,next){
    try{
        let message = await Message.create({from_username: req.user.username, to_username: req.body.to_username, body : req.body.body})
        return res.json({message:message})
    }
    catch(err){
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

router.post('/:id/read', ensureLoggedIn, async function(req,res,next){
    try{
        let message = await Message.get(req.params.id)
        if(req.user.username !== message.to_user.username){
            throw new ExpressError('Error: cannot read this message', 401)
        }
        else{
            let msg = await Message.markRead(req.params.id)
        }
        return res.json({message})
    }
    catch(err){
        return next(err)
    }
})

module.exports = router;