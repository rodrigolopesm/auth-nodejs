import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
const orders = [
  {
    id: 1,
    uid: "bob",
    items: [
      {
        name: "item1",
        single_price: "10.00",
        count: 2,
        currency: "USD",
      },
    ],
  },
  {
    id: 2,
    uid: "alice",
    items: [
      {
        name: "item2",
        single_price: "20.00",
        count: 1,
        currency: "USD",
      },
    ],
  },
  {
    id: 3,
    uid: "gremio",
    items: [
      {
        name: "item3",
        single_price: "15.00",
        count: 3,
        currency: "USD",
      },
    ],
  },
];
const users = [
  {
    uid: "bob",
    password: "password123",
  },
  {
    uid: "alice",
    password: "mypassword",
  },
];

app.get("/orders", verifyToken, (req, res) => {
  res.json(orders.filter((order) => order.uid === req.user.uid));
});
app.get("/users", (req, res) => {
  res.json(users);
});

app.post("/users", async (req, res) => {
  try {
    const hashedPwd = await bcrypt.hash(req.body.pwd, 10);
    const user = { uid: req.body.uid, pwd: hashedPwd };
    users.push(user);
    res.status(201).json(user);
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  const user = users.find((u) => u.uid === req.body.uid);
  if (!user) {
    return res.status(400).json({ message: "Cannot find user" });
  }
  try {
    if (await bcrypt.compare(req.body.pwd, user.pwd)) {
      const uid = req.body.uid;
      const jwtUser = { uid: uid };
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
      res.json({ accessToken: accessToken });
    } else {
      res.status(403).json({ message: "User or password incorrect" });
    }
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  console.log("Auth Header:", authHeader);
  const accessToken = authHeader && authHeader.split(" ")[1];
  console.log("Access Token:", accessToken);
  if (accessToken == null) return res.sendStatus(401);

  jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(3001);
