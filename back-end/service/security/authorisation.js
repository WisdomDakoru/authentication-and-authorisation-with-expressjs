const jwt = require("jsonwebtoken");
require("dotenv").config();
const config = process.env;

const authorisation = (requiredRole) => {
  return (req, res, next) => {
    // Extract the token from signed cookies
    const userCookies = req.signedCookies;
    const xAccessToken = userCookies?.user?.token;

    // Log the token for debugging purposes
    console.log("Access Token:", xAccessToken);

    if (!xAccessToken) {
      return res.status(401).send({
        auth: false,
        message: "Token is not provided.",
        status: 401,
        payload: null,
      });
    }

    try {
      // Verify the token using the secret key
      const decoded = jwt.verify(xAccessToken, config.TOKEN_KEY);

      // Get the user's account type from the decoded token
      const userRole = decoded?.user?.account_type;

      // Compare the user's role with the required role
      if (convertToRole(userRole) >= convertToRole(requiredRole)) {
        return next(); // User is authorized, proceed to the next middleware
      } else {
        return res.status(403).send({
          auth: false,
          message: "You do not have permission to access this resource.",
          status: 403,
          payload: null,
        });
      }
    } catch (err) {
      console.log("Token verification failed:", err.message);
      return res.status(401).send({
        auth: false,
        message: "Invalid or expired token.",
        status: 401,
        payload: null,
      });
    }
  };
};

// Helper function to convert role names to numeric values
const convertToRole = (role) => {
  switch (role) {
    case "user":
      return 1;
    case "admin":
      return 2;
    default:
      return 0;
  }
};

module.exports = authorisation;