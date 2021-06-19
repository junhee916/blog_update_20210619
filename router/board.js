const express = require('express')
const boardModel = require('../model/board')
const multer = require('multer')
const checkAuth = require('../middleware/check-auth')
const router = express.Router()

const storage = multer.diskStorage(
    {
        destination : function(req, file, cb){
            cb(null, './uploads')
        },
        filename : function(req, file, cb){
            cb(null, file.originalname)
        }
    }
)

const fileFilter = (req, file, cb) => {

    if(file.mimetype === 'image/jpeg' || file.mimetype === 'image/png'){
        cb(null, true)
    }
    else{
        cb(null, false)
    }
}

const upload = multer(
    {
        storage : storage,
        limit : {
            filesize : 1024*1024*5
        },
        fileFilter : fileFilter
    }
)

// total get board
router.get('/', async (req, res) => {

    try{
        const boards = await boardModel.find()
        .populate('user', ['email'])

        res.json({
            msg : "get boards",
            count : boards.length,
            boardInfo : boards.map(board => {
                return{
                    id : board.id,
                    user : board.user,
                    contents : board.contents,
                    boardImage : board.boardImage
                }
            })
        })
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

// detail get board
router.get('/:boardId', checkAuth, async (req, res) => {

    const id = req.params.boardId

    try{
        const board = await boardModel.findById(id)
        .populate('user', ['email'])

        if(!board){
            return res.status(401).json({
                msg : 'no board id'
            })
        }
        else{
            res.json({
                msg : "get board",
                boardInfo : {
                    id : board.id,
                    user : board.user,
                    contents : board.contents,
                    boardImage : board.boardImage
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

// register board
router.post('/', checkAuth, upload.single('boardImage'), async(req, res) => {

    const {user, contents} = req.body

    const newBoard = new boardModel(
        {
            user,
            contents,
            boardImage : req.file.path
        }
    )

    try{
        const board = await newBoard.save()

        res.json({
            msg : "register board",
            boardInfo : {
                id : board.id,
                user : board.user,
                contents : board.contents,
                boardImage : board.boardImage
            }
        })
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

// update board
router.patch('/:boardId', checkAuth, async (req, res) => {

    const id = req.params.boardId

    const updateOps = {}

    for(const ops of req.body){
        updateOps[ops.propName] = ops.value
    }

    try{

        const board = await boardModel.findByIdAndUpdate(id, {$set : updateOps})

        if(!board){
            return res.status(401).json({
                msg : "no board id"
            })
        }
        else{
            res.json({
                msg : "update board by " + id
            })
        }
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

// total delete board
router.delete('/', async (req, res) => {

    try{
        await boardModel.remove()

        res.json({
            msg : "delete boards"
        })
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
})

// detail delete board
router.delete('/:boardId', checkAuth, async (req, res) => {

    const id = req.params.boardId
    
    try{
        const board = await boardModel.findByIdAndRemove(id)

        if(!board){
            return res.status(401).json({
                msg : "no board id"
            })
        }
        else{
            res.json({
                msg : "delete board by " + id
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