require('./utils.js');
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const saltRounds = 12;

const app = express();
const PORT = process.env.PORT || 3000;
const expireTime = 24 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;


const { database } = include('databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('users');

app.set('view engine', 'ejs');


app.use(express.static(__dirname + '/public'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    crypto: { secret: mongodb_session_secret }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

function requireLogin(req, res, next) {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }
    if (req.session.user_type !== 'admin') {
        return res.status(403).render('403', { navLinks: navLinks(req) });
    }
    next();
}

// nav
function navLinks(req) {
    const links = [{ href: '/', label: 'Home' }];
    if (req.session.authenticated) {
        links.push({ href: '/members', label: 'Members' });
        if (req.session.user_type === 'admin') {
            links.push({ href: '/admin', label: 'Admin' });
        }
        links.push({ href: '/logout', label: 'Logout' });
    } else {
        links.push({ href: '/login', label: 'Login' });
        links.push({ href: '/signup', label: 'Sign Up' });
    }
    return links;
}



// Home
app.get('/', (req, res) => {
    res.render('index', {
        authenticated: req.session.authenticated || false,
        name: req.session.name || '',
        navLinks: navLinks(req)
    });
});

// Sign Up 
app.get('/signup', (req, res) => {
    res.render('signup', { error: null, navLinks: navLinks(req) });
});

app.post('/submitUser', async (req, res) => {
    const { name, email, password } = req.body;

    // Field presence checks
    if (!name) {
        return res.render('signup', { error: 'Name is required.', navLinks: navLinks(req) });
    }
    if (!email) {
        return res.render('signup', { error: 'Email address is required.', navLinks: navLinks(req) });
    }
    if (!password) {
        return res.render('signup', { error: 'Password is required.', navLinks: navLinks(req) });
    }

    // Joi
    const schema = Joi.object({
        name:     Joi.string().max(50).required(),
        email:    Joi.string().email().required(),
        password: Joi.string().max(100).required()
    });
    const { error } = schema.validate({ name, email, password });
    if (error) {
        return res.render('signup', { error: error.details[0].message, navLinks: navLinks(req) });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({
        name,
        email,
        password: hashedPassword,
        user_type: 'user'
    });

    req.session.authenticated = true;
    req.session.name  = name;
    req.session.email = email;
    req.session.user_type = 'user';
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

// Login 
app.get('/login', (req, res) => {
    res.render('login', { error: null, navLinks: navLinks(req) });
});

app.post('/loggingin', async (req, res) => {
    const { email, password } = req.body;

    // Joi
    const schema = Joi.object({
        email:    Joi.string().email().required(),
        password: Joi.string().max(100).required()
    });
    const { error } = schema.validate({ email, password });
    if (error) {
        return res.render('login', { error: 'Invalid email or password.', navLinks: navLinks(req) });
    }

    const result = await userCollection
        .find({ email })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();

    if (result.length !== 1) {
        return res.render('login', { error: 'User and password not found.', navLinks: navLinks(req) });
    }

    const user = result[0];
    if (await bcrypt.compare(password, user.password)) {
        req.session.authenticated = true;
        req.session.name      = user.name;
        req.session.email     = user.email;
        req.session.user_type = user.user_type || 'user';
        req.session.cookie.maxAge = expireTime;
        return res.redirect('/members');
    }

    return res.render('login', { error: 'Invalid email/password combination.', navLinks: navLinks(req) });
});

// Members
app.get('/members', requireLogin, (req, res) => {
    const images = ['fluffy.gif', 'gabby.jpg', 'socks.gif'];
    res.render('members', {
        name:     req.session.name,
        images,
        navLinks: navLinks(req)
    });
});

// Admin 
app.get('/admin', requireAdmin, async (req, res) => {
    const users = await userCollection.find().project({ name: 1, email: 1, user_type: 1 }).toArray();
    res.render('admin', { users, navLinks: navLinks(req) });
});

// Promote user to admin
app.get('/promote', requireAdmin, async (req, res) => {
    const schema = Joi.string().email().required();
    const { error } = schema.validate(req.query.email);
    if (error) return res.redirect('/admin');

    await userCollection.updateOne(
        { email: req.query.email },
        { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
});

// Demote user to regular user
app.get('/demote', requireAdmin, async (req, res) => {
    const schema = Joi.string().email().required();
    const { error } = schema.validate(req.query.email);
    if (error) return res.redirect('/admin');

    await userCollection.updateOne(
        { email: req.query.email },
        { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// 404
app.use((req, res) => {
    res.status(404).render('404', { navLinks: navLinks(req) });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
