const express = require('express');
const app = express();
const session = require('express-session');
const usersModel = require('./models/w1users');
const bcrypt = require('bcrypt');
const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * milliseconds)
const saltRounds = 12;

var MongoDBStore = require('connect-mongodb-session')(session);


const dotenv = require('dotenv');
dotenv.config();


var dbStore = new MongoDBStore({
  // uri: 'mongodb://localhost:27017/connect_mongodb_session_test',
  uri: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`,
  collection: 'mySessions'
});


// replace the in-memory array session store with a database session store
app.use(session({
  secret: 'the secret is sky color is blue ', // bad secret
  store: dbStore,
  resave: false,
  saveUninitialized: false,
}));

// public routes
app.get('/', (req, res) => {
  res.send(`<h1> Hello World </h1>
  <a href="/login">Login</a>
  <a href="/signUp">Sign Up</a>`);
});


app.get('/login', (req, res) => {
  res.send(`
    Login
    <form action="/login" method="post">
      <input type="text" name="username" placeholder="Enter your username" />
      <input type="password" name="password" placeholder="Enter your password" />
      <input type="submit" value="Login" />
    </form>
  `)

});

app.get("/signUp", (req, res) => {
  var html = `
  create user
  <form action='/submitUser' method='POST'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
  </form>
  `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ username, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signUp");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
  });
  console.log("Inserted user");

  var html = "successfully created user";
  res.send(html);
});

// GLOBAL_AUTHENTICATED = false;
app.use(express.urlencoded({ extended: false }))
// built-in middleware function in Express. It parses incoming requests with urlencoded payloads and is based on body-parser.
const Joi = require('joi');
app.use(express.json()) // built-in middleware function in Express. It parses incoming requests with JSON payloads and is based on body-parser.
app.post('/login', async (req, res) => {
  // set a global variable to true if the user is authenticated

  // sanitize the input using Joi

  const schema = Joi.object({
    password: Joi.string()
  });

  try {
    const value = await schema.validateAsync({ password: req.body.password });  
  } catch (error) {
    console.log(error);
    console.log("The password is not valid");
    return
  }

  try {
    const result = await usersModel.findOne({
      username: req.body.username
    })

    if (bcrypt.compareSync(req.body.password, result?.password)) {
      req.session.GLOBAL_AUTHENTICATED = true;
      req.session.loggedUsername = req.body.username;
      req.session.loggedPassword = req.body.password;
      res.redirect('/members');
      console.log(GLOBAL_AUTHENTICATED);
    } else {
      res.send(`wrong password
      <a href="/login">Try Again</a>`)
      
    }

  } catch (error) {
    console.log(error);
  }

});

// only for authenticated users
const authenticatedOnly = (req, res, next) => {
  if (!req.session.GLOBAL_AUTHENTICATED) {
    res.redirect('/');
  }
  next(); // allow the next route to run
};
app.use(authenticatedOnly);

app.use(express.static('public')) // built-in middleware function in Express. It serves static files and is based on serve-static.

app.get('/members', (req, res) => {
  // serve one of the three images randomly
  // generate a random number between 1 and 3
  const randomImageNumber = Math.floor(Math.random() * 9) + 1;
  const imageName = `00${randomImageNumber}.png`;
  HTMLResponse = `
    <h1> Protected Route </h1>
    <br>
    <img src="${imageName}" />
    <br>
    <a href="/logout">Logout</a>
    `
  res.send(HTMLResponse);
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  var html = `
    You are logged out.
    <a href='/'>Home</a>
    `;
  res.send(html);
});

app.get('*', (req, res) => {
  res.status(404).send('<h1> 404 Page not found</h1>');
});

// only for admins
const protectedRouteForAdminsOnlyMiddlewareFunction = async (req, res, next) => {
  try {
    const result = await usersModel.findOne({ username: req.session.loggedUsername }
    )
    if (result?.type != 'administrator') {
      return res.send('<h1> You are not an admin </h1>')
    }
    next(); // allow the next route to run
  } catch (error) {
    console.log(error);
  }
};
app.use(protectedRouteForAdminsOnlyMiddlewareFunction);

app.get('/protectedRouteForAdminsOnly', (req, res) => {
  res.send('<h1> protectedRouteForAdminsOnly </h1>');
});

app.get('*', (req, res) => {
  res.status(404).send('<h1> 404 Page not found</h1>');
});




module.exports = app;