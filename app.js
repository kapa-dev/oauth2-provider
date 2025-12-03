import dotenv from "dotenv";
dotenv.config();

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import session from "express-session";
import OAuthServer from "@node-oauth/express-oauth-server";
import bodyParser from "body-parser";
import model from "./model.js";

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.oauth = new OAuthServer({
  model,
  allowBearerTokensInQueryString: true,
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// AUTHORIZATION ENDPOINT (simulate "auto-login")
// ---------------------------------------------------------------------------
app.get("/authorize", (req, res, next) => {
  // we simulate user login
  // const user = { id: "1" };
  // return app.oauth.authorize({
  //   authenticateHandler: { handle: () => user }
  // })(req, res);

  if (!req.session.user) {
    const qs = new URLSearchParams(req.query).toString();
    const returnTo = encodeURIComponent(`/authorize?${qs}`);
    return res.redirect(`/login?returnTo=${returnTo}`)
  }

  next();
}, app.oauth.authorize({
  authenticateHandler: {
    handle: req => req.session.user
  }
}));

app.get("/login", (req, res) => {
  const returnTo = req.query.returnTo || "/authorize";

  // read the HTML file
  let filePath = path.join(__dirname, "views", "login.html");
  let html = fs.readFileSync(filePath, "utf8");

  // replace placeholder with actual returnTo
  html = html.replace('{{RETURN_TO}}', returnTo.replace(/"/g, '&quot;'));

  res.send(html);
});

app.post("/login", async (req, res) => {
  const { username, password, returnTo } = req.body;

  const user = await model.getUser(username, password);
  if (!user) {
    return res.status(401).send("Invalid credentials");
  }

  req.session.user = user;

  const redirectUrl = decodeURIComponent(returnTo || "/authorize");
  return res.redirect(redirectUrl);
});

// ---------------------------------------------------------------------------
// TOKEN ENDPOINT
// ---------------------------------------------------------------------------
app.post("/token", app.oauth.token());

// ---------------------------------------------------------------------------
// PROTECTED RESOURCE
// ---------------------------------------------------------------------------
app.get("/me", app.oauth.authenticate(), (req, res) => {
  const accessTokenData = res.locals.oauth.token;

  if (!accessTokenData || !accessTokenData.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const user = accessTokenData.user;

  return res.json({
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
  });
});

app.get("/logout", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  const userId = req.session.user.id;

  // Destroy session
  req.session.destroy(err => {
    if (err) return res.status(500).send("Logout failed");

    // Clear cookie
    res.clearCookie("connect.sid");

    // Optionally revoke all refresh tokens for this user
    for (const token in model.memory?.refreshTokens) {
      if (model.memory.refreshTokens[token].user.id === userId) {
        delete model.memory.refreshTokens[token];
      }
    }

    // Redirect to login
    return res.redirect("/login");
  });
});

const PORT = process.env.PORT || 3333;
app.listen(PORT, () =>
  console.log(`OAuth2 In-Memory Server running at http://localhost:${PORT}`)
);
