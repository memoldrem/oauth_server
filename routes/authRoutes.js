const express = require('express');
const registerController = require('../controllers/registerController');
const loginController = require('../controllers/loginController');
const authorizeController = require('../controllers/authorizeController');
const router = express.Router();
const rateLimit = require('express-rate-limit');


const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

router.get('/', loginLimiter, loginController.getLogin);
router.get('/register', registerController.getRegister);
router.post('/register', registerController.postRegister);
router.get('/login', loginLimiter, loginController.getLogin);
router.post('/login', loginLimiter, loginController.postLogin);
router.get('/authorize', loginLimiter, authorizeController.getAuthorize);
router.post('/authorize', loginLimiter, authorizeController.postAuthorize);
router.post('/logout', loginController.logout);

module.exports = router;
