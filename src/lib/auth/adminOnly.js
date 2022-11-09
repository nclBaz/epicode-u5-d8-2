import createHttpError from "http-errors"

export const adminOnlyMiddleware = (req, res, next) => {
  if (req.user.role === "Admin") {
    next()
  } else {
    next(createHttpError(403, "Admin only endpoint!"))
  }
}

/*
const roleChecker = arrayOfRoles => (req, res, next) => {
  if (arrayOfRoles.includes(req.user.role)) {
    next()
  } else {
    next(createHttpError(403, "Admin only endpoint!"))
  }
}

roleChecker(["Admin", "Manager"])

roleChecker(["Admin", "Manager", "User"])
*/
