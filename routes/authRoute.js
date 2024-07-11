const express = require("express");
const {
  userRegistration,
  accountVerificationByURL,
  userLogin,
  resendAccountVerification,
  userLogout,
  adminLogin,
  loggedInUser,
  loggedInAdmin,
  forgotPasswordReset,
  resetPassword,
} = require("../controllers/authControllers.js");
const { authMiddleware, isAdmin } = require("../middlewares/authMiddleware.js");

//express init
const authRoute = express.Router();

//create routes
authRoute.route("/register").post(userRegistration);
authRoute.route("/register/:ref").post(userRegistration);
authRoute.route("/login").post(userLogin);
authRoute.route("/admin").post(adminLogin);
authRoute.route("/logOut").post(userLogout);
authRoute.route("/login/:token").post(accountVerificationByURL);
authRoute.route("/resendToken/:email").get(resendAccountVerification);
authRoute.route("/forgotPassReset").post(forgotPasswordReset);
authRoute.route("/resetPass/:token").post(resetPassword);

authRoute.route("/loggedInUser").get(authMiddleware, loggedInUser);
authRoute.route("/loggedInAdmin").get(authMiddleware, isAdmin, loggedInAdmin);

// export
module.exports = authRoute;
