const express = require('express');
const router = express.Router();
const tokenController = require('../controllers/tokenController');


router.get('/callback', tokenController.getCallback);
router.post('/refresh', tokenController.postRefresh);


module.exports = router;