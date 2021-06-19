const jwt = require('jsonwebtoken')

module.exports = async (req, res, next) => {

    try{
        const token = req.headers.authorization.split(' ')[1]

        const decode = jwt.verify(token, process.env.SECRET_KEY)

        req.userData = decode;

        next();
    }
    catch(err){
        res.status(500).json({
            msg : err.message
        })
    }
} 