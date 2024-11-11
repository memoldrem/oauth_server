// server.js
const express = require('express');
const app = express();
const port = 3000;

// var indexRouter = require('./routes/');
var authRouter = require('./passport');

app.set('view engine', 'ejs');

app.use('/', authRouter);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
