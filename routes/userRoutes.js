const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const checkAccessTokenValidity = require('../middleware/checkTokenValidity');


router.get('/dashboard', checkAccessTokenValidity, userController.getDashboard);

module.exports = router;