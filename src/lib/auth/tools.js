import createHttpError from "http-errors"
import jwt from "jsonwebtoken"
import UsersModel from "../../users/model.js"

export const createTokens = async user => {
  // 1. Given the user, it creates 2 tokens (accessToken, refreshToken)
  const accessToken = await createAccessToken({ _id: user._id, role: user.role })
  const refreshToken = await createRefreshToken({ _id: user._id })

  // 2. Refresh token should be saved in db
  user.refreshToken = refreshToken
  await user.save()

  return { accessToken, refreshToken }
}

const createAccessToken = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15m" }, (err, token) => {
      if (err) reject(err)
      else resolve(token)
    })
  )

export const verifyAccessToken = accessToken =>
  new Promise((res, rej) =>
    jwt.verify(accessToken, process.env.JWT_SECRET, (err, originalPayload) => {
      if (err) rej(err)
      else res(originalPayload)
    })
  )

const createRefreshToken = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, process.env.REFRESH_SECRET, { expiresIn: "1w" }, (err, token) => {
      if (err) reject(err)
      else resolve(token)
    })
  )

const verifyRefreshToken = accessToken =>
  new Promise((res, rej) =>
    jwt.verify(accessToken, process.env.REFRESH_SECRET, (err, originalPayload) => {
      if (err) rej(err)
      else res(originalPayload)
    })
  )

export const verifyRefreshAndCreateNewTokens = async currentRefreshToken => {
  try {
    // 1. Check the integrity and expiration date of refresh token. We gonna catch potential errors
    const refreshTokenPayload = await verifyRefreshToken(currentRefreshToken)

    // 2. If the token is valid, let's compare it with the one we have in db
    const user = await UsersModel.findById(refreshTokenPayload._id)
    if (!user) throw new createHttpError(404, `User with id ${refreshTokenPayload._id} not found!`)
    if (user.refreshToken && user.refreshToken === currentRefreshToken) {
      // 3. If everything is fine --> create 2 new tokens (saving refresh token in db)
      const { accessToken, refreshToken } = await createTokens(user)
      return { accessToken, refreshToken }
    } else {
      throw new createHttpError(401, "Refresh token not valid!")
    }
  } catch (error) {
    // 4. In case of errors --> catch'em and send 401
    throw new createHttpError(401, "Refresh token not valid!")
  }
}
