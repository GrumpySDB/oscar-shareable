const jwt = require('jsonwebtoken');

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    // Return JSON instead of HTML on auth failure
    return res.status(401).json([]);
  }

  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // attach user info
    next();
  } catch (err) {
    // Return JSON on invalid token
    return res.status(401).json([]);
  }
}

module.exports = { authenticate };
