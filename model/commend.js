const mongoose = require('mongoose')

const commendSchema = mongoose.Schema(
    {
        user : {
            type : mongoose.Schema.Types.ObjectId,
            ref : 'user'
        },
        board : {
            type : mongoose.Schema.Types.ObjectId,
            ref : 'board',
            require : true
        },
        commend : {
            type : String,
            required : true
        }
    },
    {
        timestamps : true
    }
)

module.exports = mongoose.model('commend', commendSchema)