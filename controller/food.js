const path = require("path");
const Food = require("../models/Food");
const ErrorResponse = require("../utils/errorResponse");
const asyncHandler = require("../middleware/async");
const geocoder = require("../utils/geocoder");

// @desc          Get All Foods
// @route         GET /api/v1/foods
// @access        Public
exports.getFoods = asyncHandler(async (req, res, next) => {
  res.status(200).json(res.advancedResults);
});

// @desc          Get Single Food
// @route         GET /api/v1/foods/:id
// @access        Public
exports.getFood = asyncHandler(async (req, res, next) => {
  const food = await Food.findById(req.params.id);
  if (!food) {
    return next(
      new ErrorResponse(`Food Not Found with id of ${req.params.id}`, 404)
    );
  }
  res.status(201).json({
    success: true,
    data: food,
  });
});

// @desc          Create new Food
// @route         POST /api/v1/foods
// @access        Private
exports.createFood = asyncHandler(async (req, res, next) => {
  const food = await Food.create(req.body);
  res.status(201).json({
    success: true,
    data: food,
  });
});

// @desc          Update Food
// @route         UPDATE /api/v1/foods/:id
// @access        Private
exports.updateFood = asyncHandler(async (req, res, next) => {
  const food = await Food.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!food) {
    return next(
      new ErrorResponse(`Food Not Found with id of ${req.params.id}`, 404)
    );
  }

  res.status(200).json({ success: true, data: food });
});

// @desc          Delete Food
// @route         DELETE /api/v1/foods/:id
// @access        Private
exports.deleteFood = asyncHandler(async (req, res, next) => {
  const food = await Food.findById(req.params.id);

  if (!food) {
    return next(
      new ErrorResponse(`Food Not Found with id of ${req.params.id}`, 404)
    );
  }

  food.remove();

  res.status(200).json({ success: true, data: {} });
});

// @desc          GET Food Within a Radius
// @route         GET /api/v1/foods/radius/:zipcode/:distance
// @access        Private
exports.getFoodInRadius = asyncHandler(async (req, res, next) => {
  const { zipcode, distance } = req.params;

  // Get Lattitude and Longitude
  const location = await geocoder.geocode(zipcode);
  const lat = location[0].latitude;
  const lng = location[0].longitude;

  // Calculate the radius
  // Earth Radius = 3,963 mil / 6,375 KM
  const radius = distance / 3963;

  const foods = await Food.find({
    location: {
      $geoWithin: { $centerSphere: [[lng, lat], radius] },
    },
    book: false,
  });

  res.status(200).json({
    success: true,
    count: foods.length,
    data: foods,
  });
});

// @desc          Upload Hotel Photo
// @route         PUT /api/v1/foods/:id/photo
// @access        Private
exports.hotelPhotoUpload = asyncHandler(async (req, res, next) => {
  const food = await Food.findById(req.params.id);

  if (!food) {
    return next(
      new ErrorResponse(`Hotel Not Found with id of ${req.params.id}`, 404)
    );
  }

  if (!req.files) {
    return next(new ErrorResponse(`Please Upload a File`, 400));
  }

  const file = req.files.filepond;

  // Make sure image is a photo
  if (!file.mimetype.startsWith("image")) {
    return next(new ErrorResponse(`Please Upload a Valid Image`, 400));
  }

  // Check File Size
  if (file.size > process.env.MAX_FILE_UPLOAD) {
    return next(
      new ErrorResponse(
        `Please Upload a Image less that ${process.env.MAX_FILE_UPLOAD}`,
        400
      )
    );
  }

  // Create Custom File Name
  file.name = `photo_${food._id}${path.parse(file.name).ext}`;

  // Upload the file
  file.mv(`${process.env.FILE_UPLOAD_PATH}/${file.name}`, async (err) => {
    if (err) {
      console.error(err);
      return next(new ErrorResponse(`Problem with file upload`, 500));
    }

    await Food.findByIdAndUpdate(req.params.id, { photo: file.name });
    res.status(200).json({
      success: true,
      data: file.name,
    });
  });
});
