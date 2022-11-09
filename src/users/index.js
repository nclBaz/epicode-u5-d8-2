import express from "express"
import createHttpError from "http-errors"
import { adminOnlyMiddleware } from "../lib/auth/adminOnly.js"
import { basicAuthMiddleware } from "../lib/auth/basicAuth.js"
import { createAccessToken } from "../lib/auth/tools.js"
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

usersRouter.get("/", basicAuthMiddleware, async (req, res, next) => {
  try {
    const users = await UsersModel.find({})
    res.send(users)
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/me", basicAuthMiddleware, async (req, res, next) => {
  try {
    res.send(req.user)
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/me", basicAuthMiddleware, async (req, res, next) => {
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

usersRouter.delete("/me", basicAuthMiddleware, async (req, res, next) => {
  try {
    await UsersModel.findByIdAndDelete(req.user._id)
    res.status(204).send()
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/:userId", basicAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
  try {
    const user = await UsersModel.findById(req.params.userId)
    res.send(user)
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/:userId", basicAuthMiddleware, adminOnlyMiddleware, async (req, res, next) => {
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
      // 3.1 If credentials are fine --> generate an access token (JWT) and send it back as a response
      const accessToken = await createAccessToken({ _id: user._id, role: user.role })
      res.send({ accessToken })
    } else {
      // 3.2 If credentials are NOT ok --> trigger an error 401
      next(createHttpError(401, `Credentials are not ok!`))
    }
  } catch (error) {
    next(error)
  }
})

export default usersRouter
