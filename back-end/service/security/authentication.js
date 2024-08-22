const jwt = require("jsonwebtoken");
require("dotenv").config();
const config = process.env;

const tokenVerification = (req, res, next) => {
  // Extract token from the Authorization header
  let token = req.headers.authorization && req.headers.authorization.split(" ")[1];

  // Fallback to signed cookies if necessary
  if (!token && req.signedCookies?.user?.token) {
    token = req.signedCookies.user.token;
  }

  // Return an error if no token is found
  if (!token) {
    return res.status(403).send({
      auth: false,
      message: "Token is not provided.",
      status: 403,
    });
  }

  try {
    // Verify the token using the secret key from environment variables
    const decoded = jwt.verify(token, config.TOKEN_KEY);

    // Attach the decoded user info to the request object
    req.user = decoded;
  } catch (err) {
    console.log("Failed to authenticate token.");
    return res.status(401).send({
      auth: false,
      message: "Failed to authenticate token.",
      status: 401,
    });
  }

  // Proceed to the next middleware
  return next();
};

module.exports = tokenVerification;
