const mongoose = require('mongoose')

const boardSchema = mongoose.Schema(
    {
        user : {
            type : mongoose.Schema.Types.ObjectId,
            ref : 'user',
            required : true
        },
        contents : {
            type : String,
            required : true
        },
        boardImage : {
            type : String,
            required : true
        }
    },
    {
        timestamps : true
    }
)

module.exports = mongoose.model('board', boardSchema)