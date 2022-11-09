import createHttpError from "http-errors"
import { verifyAccessToken } from "./tools.js"

export const JWTAuthMiddleware = async (req, res, next) => {
  // 1. Check if authorization header is in the request, if it is not --> 401
  if (!req.headers.authorization) {
    next(createHttpError(401, "Please provide Bearer Token in the authorization header"))
  } else {
    try {
      // 2. If authorization header is there, we should extract the token from it
      // "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MzZiNzgzYThmNWU1YzExYjBhOGM1ZDQiLCJyb2xlIjoiVXNlciIsImlhdCI6MTY2Nzk4ODg2OCwiZXhwIjoxNjY4NTkzNjY4fQ.nfhcb800U8_lcXEqSBHOt92T1mMMEStECBDleyirW2o"
      const accessToken = req.headers.authorization.replace("Bearer ", "")

      // 3. Verify the token (check integrity and check expiration date)
      const payload = await verifyAccessToken(accessToken)

      // if everything is fine we should get back the payload {_id: "1oi2j3oij12o3jji", role:"User"}
      // 4.1 If token was fine --> next
      req.user = {
        _id: payload._id,
        role: payload.role,
      }
      next()
    } catch (error) {
      // 4.2 If token is NOT ok, or in any case jsonwebtoken lib throw some error --> 401
      console.log(error)
      next(createHttpError(401, "Token not valid!"))
    }
  }
}
