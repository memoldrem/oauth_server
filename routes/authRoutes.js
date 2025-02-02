const express = require('express');
const registerController = require('../controllers/registerController');
const loginController = require('../controllers/loginController');
const authorizeController = require('../controllers/authorizeController');
const router = express.Router();

router.get('/', loginController.getLogin);
router.get('/register', registerController.getRegister);
router.post('/register', registerController.postRegister);
router.get('/login', loginController.getLogin);
router.post('/login', loginController.postLogin);
router.get('/authorize', authorizeController.getAuthorize);
router.post('/authorize', authorizeController.postAuthorize);
router.post('/logout', loginController.logout);

module.exports = router;





