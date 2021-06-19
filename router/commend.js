const express = require('express')
const commendModel = require('../model/commend')
const checkAuth = require('../middleware/check-auth')
const router = express.Router()

// detail get commend
router.get('/:commendId', checkAuth, async (req, res) => {

    const id = req.params.commendId

    try{
        const commend = await commendModel.findById(id)
        .populate('user', ['email'])
        .populate('board', ['contents'])

        if(!commend){
            return res.status(401).json({
                msg : "no commend id"
            })
        }
        else{
            res.json({
                msg : "get commend",
                commendInfo : {
                    id : commend.id,
                    user : commend.user,
                    board: commend.board,
                    commend : commend.commend
                }
            })
        }
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

// register commend
router.post('/', async(req, res) => {

    const {user, board, commend} = req.body

    const newCommend = new commendModel({
        user,
        board, 
        commend
    })

    try{
        const commend = await newCommend.save()

        res.json({
            msg : "register commend",
            commendInfo : {
                id : commend.id,
                user : commend.user,
                board: commend.board,
                commend : commend.commend
            }
        })
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

// update commend
router.patch('/:commendId', checkAuth, async (req, res) => {

    const id = req.params.commendId

    const updateOps = {}

    for(const ops of req.body){
        updateOps[ops.propName] = ops.value
    }

    try{
        const commend = await commendModel.findByIdAndUpdate(id, {$set : updateOps})

        if(!commend){
            return res.status(401).json({
                msg : "no commend id"
            })
        }
        else{
            res.json({
                msg : "update commend by " + id
            })
        }
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

// total delete commend 
router.delete('/', async(req, res) => {

    try{
        await commendModel.remove()
        
        res.json({
            msg : "delete commends"
        })
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

// detail delete commend 
router.delete('/:commendId', checkAuth, async (req, res) => {

    const id = req.params.commendId
    
    try{
        const commend = await commendModel.findByIdAndRemove(id)

        if(!commend){
            return res.status(401).json({
                msg : 'no commend id'
            })
        }
        else{
            res.json({
                msg : "delete commend by " + id
            })
        }
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

module.exports = router