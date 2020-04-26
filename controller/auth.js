const User = require("../models/User");
const ErrorResponse = require("../utils/errorResponse");
const asyncHandler = require("../middleware/async");
const jwt = require("jsonwebtoken");

// @desc          Register User
// @route         POST /api/v1/auth/register
// @access        Public
exports.register = asyncHandler(async (req, res, next) => {
  const { name, email, password, role } = req.body;

  // Create User
  const user = await User.create({
    name,
    email,
    password,
    role,
  });

  sendTokenResponse(user, 200, res);
});

// @desc          Login User
// @route         POST /api/v1/auth/login
// @access        Public
exports.login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;
  // Validate Email and Password
  if (!email || !password) {
    return next(new ErrorResponse("Please Provide an Email and Password", 400));
  }

  // Check For User
  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    return next(new ErrorResponse("Invalid Credentials", 401));
  }

  // Check if password matches
  const isMatch = await user.matchUserPassword(password);

  if (!isMatch) {
    return next(new ErrorResponse("Invalid Credentials", 401));
  }

  sendTokenResponse(user, 200, res);
});

// @desc          Authenticate User
// @route         POST /api/v1/auth/get-user
// @access        Private
exports.getUser = asyncHandler(async (req, res) => {
  let token = req.headers.authtoken;
  let user = await jwt.verify(token, process.env.JWT_SECRET);
  if (user) {
    user = await User.findOne({ _id: user.id });
    return res.send({
      success: true,
      data: user,
    });
  } else {
    return next(new ErrorResponse("Invalid Token", 400));
  }
});

// Get Token from model, create cookie and send response
const sendTokenResponse = (user, statusCode, res) => {
  // Create a token
  const token = user.getSignedJwtToken();
  const options = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === "production") {
    options.secure = true;
  }

  res.status(statusCode).cookie("token", token, options).json({
    success: true,
    token,
  });
};
