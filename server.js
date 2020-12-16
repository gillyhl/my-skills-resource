const express = require("express")
const config = require("config")
const R = require("ramda")
const app = express()
const bodyParser = require("body-parser")
app.use(bodyParser.json())
const READ_SKILLS_SCOPE = "read_skills"
const WRITE_SKILLS_SCOPE = "write_skills"

const OktaJwtVerifier = require('@okta/jwt-verifier')


const port = config.get("port")
const oauthClient = config.get("oauthClient")
const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: oauthClient.issuerUrl,
})

const mongoose = require("mongoose")
mongoose.connect(config.get("db.url"), {useNewUrlParser: true, useUnifiedTopology: true})
const skillSchema = new mongoose.Schema({
  userId: String,
  skills: [String],
})
const getSkills = R.pick(["skills"])
const Skill = mongoose.model('Skill', skillSchema)

const verifyAuth = scope => async (req, res, next) => {
  try {
    const { authorization } = req.headers
    if (!authorization) return res.status(401).json({
      status: 401,
      message: "authorisation header missing"
    })

    const [authType, token] = authorization.trim().split(' ')
    if (authType !== 'Bearer') return res.status(401).json({
      status: 401,
      message: "token is not bearer"
    })
    const { claims } = await oktaJwtVerifier.verifyAccessToken(token, 'api://default')
    if (!R.equals(oauthClient.id, claims.cid) && !R.contains(scope, claims.scp)) {
      return res.status(400).json({
        status: 400,
        message: "scope does not match action required"
      })
    }
    req.claims = claims
    next()
  } catch (error) {
    next(error.message)
  }
}

app.get("/", verifyAuth(READ_SKILLS_SCOPE), async (req, res) => {
  let skills = await Skill.findOne({
    userId: req.claims.uid
  })

  if (R.isNil(skills)) {
    skills = new Skill({
      userId: req.claims.uid,
      skills: ["oauth2"]
    })
    await skills.save()
  }

  res.json(getSkills(skills))
})

app.post("/", verifyAuth(WRITE_SKILLS_SCOPE), async (req, res) => {
  const {skills} = req.body
  if (!(skills instanceof Array)) {
    res.status(401).json({
      message: "Skills must be an array"
    })
  }
  const result = await Skill.findOneAndUpdate({
    userId: req.claims.uid
  }, {
    $push: {
      skills: {$each: skills}
    }
  }, {
    new: true
  })

  res.json(getSkills(result))
})

app.listen(port, () => {
  console.log(`Listening on port: ${port}`)
})