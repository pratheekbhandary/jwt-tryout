import { sign, verify } from "jsonwebtoken";

export const createAccesstoken = (userId) => {
  return sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
};

export const createRefreshtoken = (userId) => {
  return sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });
};

export const sendAccessToken = (req, res, accessToken) =>
  res.send({
    accessToken,
    email: req.body.email,
  });

export const sendRefreshtoken = (res, refreshToken) => {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    path: "/refresh_token",
  });
};

export const isAuth = (req) => {
  const auth = req.headers["authorization"];
  if (!auth) throw new Error("You need to login");

  //Bearer adfdsgdsfsdgsdgsdasfdglknglksn
  const accessToken = auth.split(" ")[1];
  const { userId } = verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
  return userId;
};
