import jwt from "jsonwebtoken"

const payload = {
  _id: "21po321j3j21o3j",
  role: "User",
}

const secret = "mysup3rs3cr3t"
const wrongSecret = "mysup3rs3cr3tt"

const options = { expiresIn: 1 }

const token = jwt.sign(payload, secret, options)

console.log(token)

const originalPaylod = jwt.verify(
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiIyMXBvMzIxajNqMjFvM2oiLCJyb2xlIjoiVXNlciIsImlhdCI6MTY2Nzk4NTM4NCwiZXhwIjoxNjY3OTg1Mzg1fQ.1vdq5pQBWDNCz1aSu7BxG5m1jLYuXKLIbN3Sb5rzeDI",
  secret
)

console.log("ORIGINAL PAYLOAD: ", originalPaylod)

// *********************** HOW TO CONVERT A CALLBACK BASED FUNCTION INTO A PROMISE BASED FUNCTION

const createAccessToken = payload =>
  new Promise((resolve, reject) =>
    jwt.sign(payload, "mysup3rs3cr3t", options, (err, token) => {
      if (err) reject(err)
      else resolve(token)
    })
  )

const verifyAccessToken = accessToken =>
  new Promise((res, rej) =>
    jwt.verify(accessToken, "mysup3rs3cr3t", (err, originalPayload) => {
      if (err) rej(err)
      else res(originalPayload)
    })
  )

/* createAccessToken({})
  .then(accessToken => console.log(accessToken))
  .catch(err => console.log(err))

try {
  const accessToken = await createAccessToken({})
  console.log(accessToken)
} catch (error) {
  console.log(error)
} */
