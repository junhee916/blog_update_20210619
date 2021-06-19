const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const gravatar = require('gravatar')
const normalize = require('normalize-url')

const userSchema = mongoose.Schema(
    {
        name : {
            type : String
        },
        email : {
            type : String,
            required : true,
            unique : true,
            match : /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
        },
        password : {
            type : String,
            required : true
        },
        rule : {
            type : String,
            default : 'user'
        },
        profileImage : {
            type : String
        }
    },
    {
        timestamps : true
    }
)

userSchema.pre('save', async function(next){

    try{
        const avatar = normalize(
            gravatar.url(this.email, {
                s : '200',
                r : 'pg',
                d : 'mm'
            }),
            {forceHttps : true}
        )

        this.profileImage = avatar

        const salt = await bcrypt.genSalt(10)

        const passwordHash = await bcrypt.hash(this.password, salt)

        this.password = passwordHash

        next();
    }
    catch(err){
        next(err)
    }
})

userSchema.methods.comparePassword = async function(isInputPassword, cb){

    await bcrypt.compare(isInputPassword, this.password, (err, isMatch) => {
        if(err) return cb(err)
        cb(null, isMatch)
    })
}

module.exports = mongoose.model('user', userSchema)