const jwt = require("jsonwebtoken");
const User = require("../../models/userModel");
const ErrorHandler = require("../../utils/ErrorHandler");
const { promisify } = require("util");
const catchAsync = require("../../utils/catchAsync");

const createSendToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const sendToken = (user, statusCode, res) => {
  const token = createSendToken(user._id);

  res.cookie("jwt", token, {
    expires: new Date(
      Date.now() + process.env.COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    secure: process.env.NODE_ENV === "development" ? false : true,
    sameSite: process.env.NODE_ENV === "development" ? "Strict" : "None",
    httpOnly: true,
    path: "/",
  });

  res.status(statusCode).json({
    status: "success",
    token,
    user,
  });
};

// Filter only allowed fields from req.body
const filterObject = (obj, ...allowedFields) => {
  const filteredObject = {};
  Object.keys(obj).forEach((key) => {
    if (allowedFields.includes(key)) {
      filteredObject[key] = obj[key];
    }
  });
  return filteredObject;
};

exports.signUp = catchAsync(async (req, res, next) => {
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  sendToken(user, 201, res);
});

exports.logIn = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password)
    return next(new ErrorHandler("Please enter email and password", 401));

  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.comparePasswords(password, user.password)))
    return next(new ErrorHandler("Invalid email or password", 401));

  sendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  const { authorization } = req.headers;

  if (authorization && authorization.startsWith("Bearer"))
    token = authorization.split(" ")[1];
  else if (req.cookies.jwt) token = req.cookies.jwt;

  if (!token)
    return next(
      new ErrorHandler(
        "You are not logged in! Please log in to access this route.",
        401
      )
    );

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const currentUser = await User.findById(decoded.id);
  if (!currentUser)
    return next(
      new ErrorHandler("The user belonging to this token no longer exists.", 401)
    );

  if (currentUser.passwordChangedAfter(decoded.iat))
    return next(
      new ErrorHandler("User recently changed password. Please log in again.", 401)
    );

  req.user = currentUser;
  next();
});

exports.updateMyPassword = catchAsync(async (req, res, next) => {
  const { password, passwordConfirm, newPassword } = req.body;

  const user = await User.findById(req.user._id).select("+password");

  if (!password || !(await user.comparePasswords(password, user.password)))
    return next(new ErrorHandler("Current password is incorrect", 400));

  user.password = newPassword;
  user.passwordConfirm = passwordConfirm;
  await user.save();

  sendToken(user, 200, res);
});

exports.updateMe = catchAsync(async (req, res, next) => {
  const filteredData = filterObject(req.body, "name", "email", "status");

  const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredData, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    status: "success",
    user: updatedUser,
  });
});

exports.logOut = (req, res) => {
  try {
    res.cookie("jwt", "loggedout", {
      expires: new Date(Date.now() + 10 * 1000),
      secure: process.env.NODE_ENV === "development" ? false : true,
      sameSite: process.env.NODE_ENV === "development" ? "Strict" : "None",
      httpOnly: true,
      path: "/",
    });

    res.status(200).json({ status: "success" });
  } catch (err) {
    res.status(500).json({ status: "fail", message: "Logout failed" });
  }
};

exports.deleteMe = catchAsync(async (req, res, next) => {
  const { userId } = req.params;

  await User.findByIdAndDelete(userId);

  res.status(204).json({ status: "success" });
});
