import bcrypt from "bcrypt"

const plainPW = "12345678"
const numberOfRounds = 11
// rounds=10 means that the algorithm will be calculated 2^10 times = 1024
// rounds=11 means that the algorithm will be calculated 2^11 times = 2048

console.log(
  `The algorithm will be calculated 2^${numberOfRounds} times --> ${Math.pow(
    2,
    numberOfRounds
  )} times`
)

console.time("hashing")
const hash = bcrypt.hashSync(plainPW, numberOfRounds)
console.timeEnd("hashing")

console.log(hash) // --> SALTED HASH --> hash("ydxuBQKBQB0xPk11tT33n12345678")

const isOK = bcrypt.compareSync(plainPW, hash)

console.log("IS OK??? ", isOK)

// BRUTE FORCE

// 111111111 --> calculate hash(111111111) --> $2b$10$ydxuBQKBQB0xPk11tT33n.UD3RfsHTdasTf7xNS4LOAbq7Ikd9cc6
// 111111112 --> calculate hash(111111112)
// 111111113 --> calculate hash(1111111113)
