const User = require("../models/User");
const Food = require("../models/Food");
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
exports.getUser = asyncHandler(async (req, res, next) => {
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

// @desc          Update user food list
// @route         UPDATE /api/v1/auth/book-food
// @access        Private
exports.updateFoodList = asyncHandler(async (req, res, next) => {
  const foodList = await User.findById(req.params.id);
  const foodId = req.body.bookFoodId;
  let arr = foodList.bookedFoodId;
  arr.push(foodId);
  const user = await User.findByIdAndUpdate(
    req.params.id,
    {
      bookedFoodId: arr,
    },
    {
      new: true,
      runValidators: true,
    }
  );
  if (!user) {
    return next(
      new ErrorResponse(`User Not Found with id of ${req.params.id}`, 404)
    );
  }
  res.status(200).json({ success: true, data: user });
});

// @desc          GET user food list
// @route         GET /api/v1/auth/get-user-food
// @access        Private

exports.getUserFood = asyncHandler(async (req, res, next) => {
  let foodIdArr = req.body.arr;
  // const foodList = await Food.find({
  //   _id: { $in: foodIdArr },
  // });
  const foodList = [];
  for (let item = 0; item < foodIdArr.length; item++) {
    let food = await Food.findOne({ _id: foodIdArr[item] });
    foodList.push(food);
  }
  if (foodList.length === 0) {
    return next(new ErrorResponse(`Food Not Found`, 404));
  }
  res.status(200).json({
    success: true,
    data: foodList,
  });
});
