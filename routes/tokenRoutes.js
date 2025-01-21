const express = require('express');
const router = express.Router();
const tokenController = require('../controllers/tokenController');


router.get('/callback', tokenController.getCallback);
router.post('/validate', tokenController.validate);



module.exports = router;