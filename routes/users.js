const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const passport = require('passport');

// User model
const User = require("../models/User");

// Login page
router.get("/login", (req, res) => res.render("login"));

// Register page page
router.get("/register", (req, res) => res.render("register"));

// Post request to the db when registering
router.post("/register", (req, res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];
  // check required fields
  if (!name || !email || !password || !password2) {
    errors.push({ msg: "Please fill in all fields" });
  }
  // check password
  if (password !== password2) {
    errors.push({ msg: "passwords do not match" });
  }
  // Check ps length
  if (password.length < 6) {
    errors.push({ msg: "password should be atleast 6 characters" });
  }
  // check for errors
  if (errors.length > 0) {
    res.render("register", {
      errors,
      name,
      email,
      password,
      password2
    });
  } else {
    // Validation passed
    User.findOne({ email: email }).then(user => {
      if (user) {
        // User exists
        errors.push({ msg: "Email already taken" });
        res.render("register", {
          errors,
          name,
          email,
          password,
          password2
        });
      } else {
        const newUser = new User({
          name: name,
          email,
          password
        });
        // hash password
        bcrypt.genSalt(10, (err, salt) =>
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            // Set password to hashed
            newUser.password = hash;
            // Save user
            newUser.save()
              .then(user => {
                req.flash('success_msg', 'You are now registered');
                res.redirect("/users/login");
              })
              .catch(err => console.log(err));
          })
        );
      }
    });
    // query the db to find an email equal to email
  }
});

// Login handle
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req, res, next);
});

router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
});

module.exports = router;
