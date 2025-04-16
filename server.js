require('dotenv').config();
const express = require("express");
const bcrypt = require('bcyptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());//解析JSON请求
app.use(cors());//允许跨域请求
app.use(helmet());
app.use(morgan('combined'));

const validateEmail = (email) => {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

const generateToken = (userId) => {
    return jwt.sign({userId},process.env.JWT_SECRET,{expiresIn: '1h'});
}


//用户注册
app.post('api/register',async(req,res,next) => {
    try {
        const {email,password} = req.body;

        if(!email || !password) {
            return res.status(400).json({error:'邮箱或密码为空'});
        }
        if(!validateEmail(email)){
            return res.status(400).json({error: '邮箱格式无效'});
        }
        if(password.length <6) {
            return res.status(400).json({error:'密码至少需要6位'});
        }
        const [existingUsers] = await pool.query('select id from users where email = ?',[email]);
        if(existingUsers.length > 0){
            return res.status(409).json({error:'邮箱已被注册'});
        }
        const hashedPassword = await bcrypt.hash(password,10);
        const [result] = await pool.query(
            'insert into users (email,password) values (?,?)',
            [email,hashedPassword]
        );
        const token = generateToken(result.insertId);
        res.status(201).json({userId:result.insertId,token});
    }catch(error) {
        next(error);
    }
})

app.post('/api/login',async(req,res,next) => {
    try{
        const {email,password} = req.body;
        if (!email || !password) {
            return res.status(400).json({error:'邮箱和密码位必填'});
        }
        const [users] = await pool.query('select * from users where email = ?',[email]);
        if(users.length === 0) {
            return res.status(401).json({error:'该邮箱未注册'});
        }
        const user = users[0];
        const validePassword = await bcrypt.compare(password,user.password);
        if(!validePassword) {
            return res.status(401).json({error:'邮箱或密码错误'});
        }

        const token = generateToken(user.id);
        res.json({userId: user.id,token});
    }catch(error){
        next(error);
    }
})

app.get('/api/me',async (req,res,next) => {
    try{
        const token = req.headers.authorization?.split(' ')[1];
        const decoded = jwt.verify(token,process.env.JWT_SECRET);
        const [users] = await pool.query('select id,email from users where id = ?',[decoded.userId]);
        if (users.length === 0) {
            return res.status(404).json({error:'用户不存在'});
        }
        res.json(users[0]);
    }catch(error){
        if(error.name === 'JsonWebTokenError'){
            return res.status(401).json({error:'无效令牌'});
        }
        next(error);
    }
})

app.use(express.static('dist'));

app.use((err,req,res,next)=>{
    console.log(err.stack);

    if(err.code === 'ER_DUP_ENTRY'){
        return res.status(409).json({error:'邮箱已被注册'});
    }

    res.status(500).json({error:"服务器内部错误"});
})

app.use((req,res) => {
    res.status(404).json({error:'路由不存在'});
})

const server = app.listen(PORT,() =>{
    console.log(`server running on port ${PORT}`);
})

process.on('SIGTERM',() => {
    console.log('SIGTERM signal recieved:closing HTTP server');
    server.close(() => {
        pool.end();
        console.log('HTTP server closed');
    })
})