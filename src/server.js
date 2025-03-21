const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const express = require('express');
const handlebars = require('express-handlebars');
const path = require('path');
const passport = require('passport');
const Auth0Strategy = require('passport-auth0');
const request = require('request-promise');
const session = require('express-session');

// loading env vars from .env file
require('dotenv').config();

const app = express();

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser(crypto.randomBytes(16).toString('hex')));
app.use(
  session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false
  })
);
app.engine('handlebars', handlebars());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/profile', (req, res) => {
  const { user } = req.session.passport;
  res.render('profile', {
    idToken: user.idToken,
    decodedIdToken: user._json
  });
});

app.get('/login', (req, res) => {
  res.status(501).send();
});

app.post('/callback', async (req, res) => {
  res.status(501).send();
});

app.get('/to-dos', async (req, res) => {
  res.status(501).send();
});

app.get('/remove-to-do/:id', async (req, res) => {
  res.status(501).send();
});

const { OIDC_PROVIDER } = process.env;
const discEnd = 'https://${OIDC_PROVIDER}/.well-known/openid-configuration';

request(discEnd)
  .then(res => {
    var oidcProviderInfo = JSON.parse(res);

    app.listen(3000, () => {
      console.log('Server running on http://localhost:3000');
    });
  })
  .catch(error => {
    console.error(error);
    console.error('Unable to get OIDC endpoints for ${OIDC_PROVIDER}');
    process.exit(1);
  });
/*
app.listen(3000, () => {
  console.log(`Server running on http://localhost:3000`);
});
*/
