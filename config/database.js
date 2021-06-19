const mongoose = require('mongoose')

const connectDB = async function(){

    try{

        mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex : true
        })

        console.log('connected mongodb...')
    }
    catch(err){
        console.log(err.message)
        process.exit(1)
    }
}

module.exports = connectDB