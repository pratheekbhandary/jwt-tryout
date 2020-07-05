import "dotenv/config";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import { verify } from "jsonwebtoken";
import { hash, compare } from "bcrypt";
import db from "./fakeDb";
import {
  createAccesstoken,
  createRefreshtoken,
  sendAccessToken,
  sendRefreshtoken,
  isAuth,
} from "./token";

const server = express();
// A middleware for easier cookie handling
server.use(cookieParser());

server.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

server.use(express.json());
server.use(express.urlencoded({ extended: true }));

server.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (email == undefined || password == undefined)
      throw new Error("email and password required");
    const user = db.find(({ email: userEmail }) => userEmail === email);
    if (user) throw new Error("User already exists");
    const hashedPassword = await hash(password, 10);
    db.push({
      id: db.length ? Math.max(...db.map(({ id }) => id)) : 0,
      email,
      password: hashedPassword,
    });
    res.status(201).send("User Created");
  } catch (err) {
    res.status(400).send({
      error: `${err.message}`,
    });
  }
});

server.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (email == undefined || password == undefined)
      throw new Error("email and password required");
    const user = db.find(({ email: userEmail }) => userEmail === email);
    if (!user) throw new Error("Invalid email or password");
    const valid = await compare(password, user.password);
    if (!valid) throw new Error("Invalid email or password");

    // if both user id and password are correct then
    // create
    //    Access Token : short life time
    //    Refresh Token : longer life time
    //        Different versions of Referesh Tokens can be created

    const accessToken = createAccesstoken(user.id);
    const refreshToken = createRefreshtoken(user.id);

    // Put the refresh token in the database
    user["refreshToken"] = refreshToken;

    //Send Referesh Token as cookie and Access Token as regular response
    sendRefreshtoken(res, refreshToken);
    sendAccessToken(req, res, accessToken);

    console.log(db);
  } catch (err) {
    console.error(err);
    res.status(400).send({
      error: `${err.message}`,
    });
  }
});

server.post("/logout", (_, res) => {
  res.clearCookie("refreshToken", { path: "/refresh_token" });
  return res.send({
    message: "Logged Out",
  });
});

server.post("/protected", (req, res) => {
  try {
    const userId = isAuth(req);
    if (userId !== null) {
      res.send({
        data: "This is protected data",
      });
    }
  } catch (err) {
    res.status(400).send({
      error: `${err.message}`,
    });
  }
});

server.post("/refresh_token", (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.send({ accessToken: "" });
  let payload = null;
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    // invalid token
    return res.send({ accessToken: "" });
  }
  // Check if valid user
  const user = db.find(({ id }) => id === payload.userId);

  if (!user) return res.send({ accessToken: "" });

  //Check if valid token
  if (user.refreshToken !== token) {
    console.log("token not matching", user.refreshToken, token);
    user["refreshToken"] = refreshToken;
    return res.send({ accessToken: "" });
  }

  const refreshToken = createRefreshtoken(user.id);
  const accessToken = createAccesstoken(user.id);

  // Put the refresh token in the database
  user["refreshToken"] = refreshToken;
  console.log({ user });

  //Send Referesh Token as cookie and Access Token as regular response
  sendRefreshtoken(res, refreshToken);
  sendAccessToken(req, res, accessToken);
});

server.listen(process.env.PORT, () =>
  console.log(`Server listening on port ${process.env.PORT}`)
);
