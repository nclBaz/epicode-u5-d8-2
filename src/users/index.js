import express from "express"
import createHttpError from "http-errors"
import { adminOnlyMiddleware } from "../lib/auth/adminOnly.js"
import { basicAuthMiddleware } from "../lib/auth/basicAuth.js"
import { JWTAuthMiddleware } from "../lib/auth/jwtAuth.js"
import { createTokens, verifyRefreshAndCreateNewTokens } from "../lib/auth/tools.js"
import UsersModel from "./model.js"

const usersRouter = express.Router()

usersRouter.post("/", async (req, res, next) => {
  try {
    const newUser = new UsersModel(req.body)
    const { _id } = await newUser.save()
    res.status(201).send({ _id })
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const users = await UsersModel.find({})
    res.send(users)
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const user = await UsersModel.findById(req.user._id)
    if (user) {
      res.send(user)
    } else {
      next(createHttpError(404, `User with Id ${req.user._id} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const updatedUser = await UsersModel.findByIdAndUpdate(req.user._id, req.body, {
      new: true,
      runValidators: true,
    })
    res.send(updatedUser)
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    await UsersModel.findByIdAndDelete(req.user._id)
    res.status(204).send()
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const user = await UsersModel.findById(req.params.userId)
    res.send(user)
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/:userId", JWTAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const user = await UsersModel.findByIdAndDelete(req.params.userId)
    if (user) {
      res.status(204).send()
    } else {
      next(createHttpError(404, `User with Id ${req.params.userId} not found!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/login", async (req, res, next) => {
  try {
    // 1. Obtain the credentials from req.body
    const { email, password } = req.body

    // 2. Verify credentials
    const user = await UsersModel.checkCredentials(email, password)

    if (user) {
      // 3.1 If credentials are fine --> generate an access token (JWT) and a refresh token and send them back as a response
      const { accessToken, refreshToken } = await createTokens(user)
      res.send({ accessToken, refreshToken })
    } else {
      // 3.2 If credentials are NOT ok --> trigger an error 401
      next(createHttpError(401, `Credentials are not ok!`))
    }
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/refreshTokens", async (req, res, next) => {
  try {
    // 1. Obtain the current refresh token from req.body
    const { currentRefreshToken } = req.body

    // 2. Check the validity of that token (check if that is not expired, check if that hasn't been compromised, check if it is the same we have in db)

    // 3. If everything is fine --> generate a new pair of tokens (accessToken2 & refreshToken2), also replacing the previous refresh token with the new one in db
    const { accessToken, refreshToken } = await verifyRefreshAndCreateNewTokens(currentRefreshToken)

    // 4. Send the tokens back as response
    res.send({ accessToken, refreshToken })
  } catch (error) {
    // 5. In case of errors --> 401
    next(error)
  }
})

export default usersRouter
