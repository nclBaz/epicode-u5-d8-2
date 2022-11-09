import createHttpError from "http-errors"
import atob from "atob"
import UsersModel from "../../users/model.js"

export const basicAuthMiddleware = async (req, res, next) => {
  // This will be our "Police Officer Middleware", which is going to check "documents" of our users.
  // If documents are ok user can have the access to the endpoint
  // Otherwise user is going to be rejected with an error (401)

  // Here we are expecting to receive an Authorization header with "Basic am9obkByYW1iby5jb206MTIzNDU2Nzg=" as value
  // this is basically just email:password encoded in Base64

  // 1. Check if Authorization header is provided, if it is not --> trigger an error (401)
  if (!req.headers.authorization) {
    next(createHttpError(401, `Please provide credentials in Authorization header!`))
  } else {
    // 2. If we obtain Authorization header, we should extract the credentials out of it (credentials are base64 encoded therefore we should also decode them)
    const base64Credentials = req.headers.authorization.split(" ")[1] // --> "am9obkByYW1iby5jb206MTIzNDU2Nzg=""
    const decodedCredentials = atob(base64Credentials) // --> "john@rambo.com:12345678"
    const [email, password] = decodedCredentials.split(":") // --> email = "john@rambo.com", password="12345678"

    // 3. Once we obtain the credentials, let's check if the user is in db and if the provided pw is ok
    const user = await UsersModel.checkCredentials(email, password)

    if (user) {
      // 4.a If credentials are ok --> you can go on
      req.user = user
      next()
    } else {
      // 4.b If credentials are NOT ok --> 401
      next(createHttpError(401, `Either email or password are wrong`))
    }
  }
}
