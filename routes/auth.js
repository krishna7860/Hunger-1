const express = require("express");
const {
  register,
  login,
  getUser,
  updateFoodList,
  getUserFood,
} = require("../controller/auth");

const router = express.Router();

router.post("/register", register);

router.post("/login", login);

router.get("/get-user", getUser);

router.put("/book-food/:id", updateFoodList);

router.post("/get-user-food", getUserFood);

module.exports = router;
