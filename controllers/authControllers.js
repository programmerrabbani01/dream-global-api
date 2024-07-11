const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const {
  isEmail,
  createOTP,
  dotsToHyphens,
  hyphensToDots,
  convertToDashedString,
} = require("../helpers/helpers.js");
const User = require("../models/User.js");
const {
  ACCESS_TOKEN,
  APP_ENV,
  ACCESS_TOKEN_EXPIRES,
  ADMIN_PATH,
} = require("../utils/secret.js");
const jwt = require("jsonwebtoken");
const AccountActivationEmail = require("../utils/AccountActivationMail.js");
const ResetPassMail = require("../utils/resetPassMail.js");
const Commission = require("../models/Commission.js");

/**
 * @DESC user registration
 * @ROUTE api/v1/auth/register
 * @METHOD POST
 * @ACCESS public
 */

const userRegistration = asyncHandler(async (req, res, next) => {
  try {
    // get body data
    const { name, userName, email, password } = req.body;

    const { ref } = req.params;

    // is empty
    if (!name || !userName || !email || !password) {
      throw new Error("all fields are required");
    }

    // Validate user name

    // if (!isUserName(userName)) throw new Error("Invalid userName format");

    // Validate email

    if (!isEmail(email)) throw new Error("Invalid email format");

    // find reference
    if (ref) {
      const referrer = await User.findOne({ userName: ref });

      // create new reference
      if (referrer) {
        const createCommission = await Commission.create({
          reference: referrer.userName,
          newUser: userName,
          commission: 0,
          status: "pending",
        });
      }
    }

    // Check for existing email

    const userEmailCheck = await User.findOne({ email });

    if (userEmailCheck) throw new Error("Email already exists");

    // Check for existing user name

    const userNameCheck = await User.find({ userName: userName });

    if (userNameCheck) throw new Error("User Name already exists");

    // Check password length
    if (password.length < 6) {
      throw new Error("Password must be at least 6 characters long");
    }

    // Hash the password
    const hashPass = await bcrypt.hash(password, 10);

    //  create a access token for account activation

    const activationCode = createOTP();

    // create verification token

    const verifyToken = jwt.sign({ email: email }, ACCESS_TOKEN, {
      expiresIn: "15m",
    });

    res.cookie("verifyToken", verifyToken);

    // activation link

    const activationLink = `${ADMIN_PATH}/login/${dotsToHyphens(verifyToken)}`;
    // send Email

    await AccountActivationEmail(email, {
      name,
      code: activationCode,
      link: activationLink,
    });

    // Create new user
    const newUser = new User({
      name,
      userName: convertToDashedString(userName),
      email,
      password: hashPass,
      accessToken: activationCode,
    });

    await newUser.save();

    // Return the new user and success message
    // response
    res.status(201).json({
      user: newUser,
      message: "Registration successfully, check your mail for verification",
    });
  } catch (error) {
    throw error;
  }
});

/**
 * @DESC User Login
 * @ROUTE /api/v1/auth/login
 * @method POST
 * @access public
 */
const userLogin = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // validation
  if (!email || !password)
    return res.status(404).json({ message: "All fields are required" });

  // find login user

  let loginUserData = null;

  if (isEmail(email)) {
    loginUserData = await User.findOne({ email: email });

    // user not found
    if (!loginUserData)
      return res.status(404).json({ message: "User not found" });
  } else {
    return res.status(404).json({
      message: "Login User Must Have A Email Address",
    });
  }

  // password check
  const passwordCheck = await bcrypt.compare(password, loginUserData.password);

  // password check
  if (!passwordCheck)
    return res.status(404).json({ message: "Wrong password" });

  // create access token
  const token = jwt.sign({ email: email }, ACCESS_TOKEN, {
    expiresIn: ACCESS_TOKEN_EXPIRES,
  });

  res.cookie("accessToken", token, {
    httpOnly: true,
    secure: APP_ENV == "Development" ? false : true,
    sameSite: "strict",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.status(200).json({
    token,
    user: loginUserData,
    message: "User Login Successful",
  });
});

/**
 * @DESC Login admin with EMAIL and password
 * @ROUTE api/v1/auth/admin
 * @METHOD POST
 * @ACCESS public
 */

const adminLogin = asyncHandler(async (req, res) => {
  //get body data
  const { email, password } = req.body;
  // is empty
  if (!email || !password) {
    throw new Error("all fields are required");
  }

  // find login user

  let loginAdminData = null;

  //find admin by email

  if (isEmail(email)) {
    loginAdminData = await User.findOne({ email: email });
  }

  //check if admin
  if (!loginAdminData) {
    throw new Error("User not found");
  }

  if (loginAdminData.role !== "admin") {
    throw new Error("Not Authorized");
  }
  // password check
  const passwordCheck = await bcrypt.compare(password, loginAdminData.password);

  // password check
  if (!passwordCheck)
    return res.status(404).json({ message: "Wrong password" });

  //Token Generated

  const token = jwt.sign({ email: email }, ACCESS_TOKEN, {
    expiresIn: ACCESS_TOKEN_EXPIRES,
  });

  //set cookie
  res.cookie("accessToken", token, {
    httpOnly: true,
    secure: APP_ENV == "Development" ? false : true,
    sameSite: "strict",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  //response
  res
    .status(200)
    .json({ token, admin: loginAdminData, message: "Login Success" });
});

/**
 * @DESC logged in user
 * @ROUTE /api/v1/auth/loggedInUser
 * @method get
 * @access public
 */
const loggedInUser = asyncHandler(async (req, res) => {
  res.status(200).json(req.me);
});

/**
 * @DESC logged in admin
 * @ROUTE /api/v1/auth/loggedInAdmin
 * @method get
 * @access public
 */
const loggedInAdmin = asyncHandler(async (req, res) => {
  res.status(200).json(req.me);
});

/**
 * @DESC account Verification By URL
 * @ROUTE /api/v1/auth/login/:token
 * @method POST
 * @access public
 */

const accountVerificationByURL = asyncHandler(async (req, res) => {
  const { token } = req.params;

  console.log(token);

  if (!token) {
    return res.status(400).json({ message: "Invalid token" });
  }

  const verifyToken = hyphensToDots(token);

  // verify the token

  const tokenCheck = jwt.verify(verifyToken, ACCESS_TOKEN);

  if (!tokenCheck) {
    return res.status(400).json({ message: " Invalid Active Request " });
  }

  // activate account now

  let activateUser = null;

  if (isEmail(tokenCheck.email)) {
    activateUser = await User.findOne({ email: tokenCheck.email });

    if (!activateUser) {
      return res.status(400).json({ message: "User not found" });
    }
  } else {
    return res.status(400).json({ message: " Auth is Undefined" });
  }

  activateUser.accessToken = null;
  activateUser.verify = true;
  activateUser.save();

  // clear token
  res.clearCookie("verifyToken");

  return res
    .status(200)
    .json({ message: " User Activation Successful", user: activateUser });
});

/**
 * @DESC resend account Verification By Link
 * @ROUTE /api/v1/auth/resendVerification/:auth
 * @method POST
 * @access public
 */

const resendAccountVerification = asyncHandler(async (req, res) => {
  const { email } = req.params;

  //  create a access token for account activation

  const activationCode = createOTP();

  // auth value manage

  let authEmail = null;
  let authUser = null;

  if (isEmail(email)) {
    authEmail = email;

    //  check authUser
    authUser = await User.findOne({ email: authEmail });

    // create verification token

    const verifyToken = jwt.sign({ email: email }, ACCESS_TOKEN, {
      expiresIn: "15m",
    });

    res.cookie("verifyToken", verifyToken);

    // activation link

    const activationLink = `${ADMIN_PATH}/login/${dotsToHyphens(verifyToken)}`;
    // send Email

    await AccountActivationEmail(email, {
      name: authUser.name,
      link: activationLink,
    });
  }

  authUser.accessToken = activationCode;
  authUser.save();

  res.status(200).json({
    user: authUser,
    message: "Activation Code Send successful",
  });
});

/**
 * @DESC User LogOut
 * @ROUTE /api/v1/auth/logOut
 * @method POST
 * @access public
 */
const userLogout = asyncHandler(async (req, res) => {
  res.clearCookie("accessToken");
  res.status(200).json({ message: "Logout successful" });
});

/**
 * @DESC forgot Password Reset
 * @ROUTE /api/v1/auth/forgotPassReset
 * @method POST
 * @access public
 */

const forgotPasswordReset = asyncHandler(async (req, res) => {
  const { email } = req.body;

  //  create a access token for account activation

  const activationCode = createOTP();

  // reset password user

  let resetPassUser = null;

  if (isEmail(email)) {
    // user email check
    resetPassUser = await User.findOne({ email: email });

    if (!resetPassUser) {
      return res.status(400).json({ message: "No User Found" });
    }

    // create verification token

    const verifyToken = jwt.sign({ email: email }, ACCESS_TOKEN, {
      expiresIn: "15m",
    });

    res.cookie("verifyToken", verifyToken);

    // activation link

    const activationLink = `${ADMIN_PATH}/forgotPass/${dotsToHyphens(
      verifyToken
    )}`;
    // send Email

    await ResetPassMail(email, {
      name: resetPassUser.name,
      link: activationLink,
    });
  } else {
    return res
      .status(400)
      .json({ message: "You Must Use Email For Registration" });
  }

  resetPassUser.accessToken = activationCode;
  resetPassUser.save();

  res.status(200).json({ message: "User Reset Password Link Send Successful" });
});

/**
 * @DESC Reset Password
 * @ROUTE /api/v1/auth/resetPass/:token
 * @method POST
 * @access public
 */

const resetPassword = asyncHandler(async (req, res) => {
  const { token } = req.params;

  const { newPass, confPass } = req.body;

  if (!newPass) {
    return res.status(400).json({ message: "New Password is Required" });
  }
  if (!confPass) {
    return res.status(400).json({ message: "Confirm Password is Required" });
  }
  if (!token) {
    return res.status(400).json({ message: "Token Not Found" });
  }

  if (newPass !== confPass) {
    return res.status(400).json({ message: "Password Not Match" });
  }

  const verifyToken = hyphensToDots(token);

  // verify the token

  const tokenCheck = jwt.verify(verifyToken, ACCESS_TOKEN);

  if (!tokenCheck) {
    return res.status(400).json({ message: " Invalid Active Request" });
  }

  // activate account now

  let resetPassUser = null;

  if (isEmail(tokenCheck.email)) {
    resetPassUser = await User.findOne({ email: tokenCheck.email });

    if (!resetPassUser) {
      return res.status(400).json({ message: "User not found" });
    }
  } else {
    return res.status(400).json({ message: " Auth is Undefined" });
  }

  // password hash
  const hashPass = await bcrypt.hash(newPass, 10);

  resetPassUser.password = hashPass;
  resetPassUser.accessToken = null;
  resetPassUser.save();

  // clear token
  res.clearCookie("verifyToken");

  return res.status(200).json({ message: " Password Reset Successful" });
});

// export
module.exports = {
  userRegistration,
  accountVerificationByURL,
  resendAccountVerification,
  userLogin,
  userLogout,
  adminLogin,
  loggedInUser,
  loggedInAdmin,
  forgotPasswordReset,
  resetPassword,
};
