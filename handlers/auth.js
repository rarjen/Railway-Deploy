const { User } = require('../models');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const util = require('../utils');

const {
    JWT_SECRET_KEY
} = process.env;

module.exports = {
    signUp: (req, res, next) => {
        return res.render('auth/register', { error: null });
    },

    signIn: (req, res, next) => {
        return res.render('auth/login', { error: null });
    },

    register: async (req, res, next) => {
        try {
            const { name, email, password, confirm_password } = req.body;
            if (password != confirm_password) return res.render('auth/register', { error: 'password doesn\'t match!' });

            const userExist = await User.findOne({ where: { email } });
            if (userExist) return res.render('auth/register', { error: 'email already used!' });

            const hashed = await bcrypt.hash(password, 10);
            const newUser = await User.create({
                name,
                email,
                password: hashed,
            });

            return res.render('auth/login', { error: null });
        } catch (err) {
            next(err);
        }
    },

    login: async (req, res, next) => {
        try {
            const { email, password } = req.body;
            const userExist = await User.findOne({ where: { email } });

            if (!userExist) return res.render('auth/login', { error: 'user not found!' });

            // check password
            const passwordMatch = await bcrypt.compare(password, userExist.password);
            if (!passwordMatch) return res.render('auth/login', { error: 'wrong password!' });

            // return token 
            return res.render('index');
        } catch (err) {
            next(err);
        }
    },

    forgotPasswordView: (req, res) => {
        return res.render('auth/forgot-password', { message: null });
    },

    forgotPassword: async (req, res, next) => {
        try {
            const { email } = req.body;

            const user = await User.findOne({ where: { email } });
            if (user) {
                const payload = { user_id: user.id };
                const token = jwt.sign(payload, JWT_SECRET_KEY);
                const link = `http://localhost:3000/auth/reset-password?token=${token}`;

                htmlEmail = await util.email.getHtml('reset-password.ejs', { name: user.name, link: link });
                await util.email.sendEmail(user.email, 'Reset your password', htmlEmail);
            }

            return res.render('auth/forgot-password', { message: 'we will send email for reset password if the email is exist on our database!' });
        } catch (err) {
            next(err);
        }
    },

    resetPasswordView: (req, res) => {
        const { token } = req.query;
        return res.render('auth/reset-password', { message: null, token });
    },

    resetPassword: async (req, res, next) => {
        try {
            const { token } = req.query;
            const { new_password, confirm_new_password } = req.body;

            console.log('TOKEN :', token);

            if (!token) return res.render('auth/reset-password', { message: 'invalid token', token });
            if (new_password != confirm_new_password) return res.render('auth/reset-password', { message: 'password doesn\'t match!', token });

            const payload = jwt.verify(token, JWT_SECRET_KEY);

            const encryptedPassword = await bcrypt.hash(new_password, 10);

            const user = await User.update({ password: encryptedPassword }, { where: { id: payload.user_id } });
            // validasi masih salah
            // if (user[0]) return res.render('auth/reset-password', { message: 'failed reset password', token });

            return res.render('auth/login', { error: null });
        } catch (err) {
            next(err);
        }
    }
};



