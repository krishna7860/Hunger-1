const express = require("express");
const {
  getFood,
  getFoods,
  createFood,
  updateFood,
  deleteFood,
  getFoodInRadius,
  hotelPhotoUpload,
} = require("../controller/food");

const Food = require("../models/Food");

const advancedResult = require("../middleware/advancedResult");

// Include other resource routers
// const courseRouter = require("./course");

const router = express.Router();

// Re Route into other resources
// router.use("/:bootcampId/courses", courseRouter);

router.route("/radius/:zipcode/:distance").get(getFoodInRadius);

router.route("/:id/photo").post(hotelPhotoUpload);

router
  .route("/")
  .get(advancedResult(Food, "courses"), getFoods)
  .post(createFood);

router.route("/:id").get(getFood).put(updateFood).delete(deleteFood);

module.exports = router;
