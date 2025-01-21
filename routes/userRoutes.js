const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const checkAccessTokenValidity = require('../middleware/checkTokenValidity');


router.get('/dashboard', userController.getDashboard);
router.get('/feed', userController.getFeed);

module.exports = router;