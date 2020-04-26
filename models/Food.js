const mongoose = require("mongoose");
const slugify = require("slugify");
const geocoder = require("../utils/geocoder");

const FoodSchema = new mongoose.Schema({
  hotelName: {
    type: String,
    required: [true, "Please add a Hotel Name"],
    unique: true,
    trim: true,
    maxlength: [50, "Name cannot be more than 50 Characters"],
  },
  slug: String,
  quantity: {
    type: Number,
    required: [true, "Please Mention Quantity of Food"],
  },
  description: {
    type: String,
    required: [true, "Please add a Detailed Description"],
    maxlength: [500, "Name cannot be more than 50 Characters"],
  },
  phone: {
    type: String,
    maxlength: [20, "Phone number cannot be longer than 20 Characters"],
    required: [true, "Phone number is required"],
  },
  email: {
    type: String,
    match: [
      /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
      "Please add a valid email",
    ],
  },
  book: {
    type: Boolean,
    default: false,
  },
  address: {
    type: String,
    required: [true, "Please add an address"],
  },
  location: {
    type: {
      type: String,
      enum: ["Point"],
    },
    coordinates: {
      type: [Number],
      index: "2dsphere",
    },
    formattedAddress: String,
    street: String,
    city: String,
    state: String,
    zipcode: String,
    country: String,
  },

  // averageCost: Number,
  photo: {
    type: String,
    default: "no-photo.jpg",
  },
  // housing: {
  //   type: Boolean,
  //   default: false
  // },
  // jobAssistance: {
  //   type: Boolean,
  //   default: false
  // },
  // jobGuarantee: {
  //   type: Boolean,
  //   default: false
  // },
  // acceptGi: {
  //   type: Boolean,
  //   default: false
  // },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Create BootCamp Slug
FoodSchema.pre("save", function (next) {
  this.slug = slugify(this.hotelName, { lower: true });
  next();
});

// Geocode Create location fields
FoodSchema.pre("save", async function (next) {
  const location = await geocoder.geocode(this.address);
  this.location = {
    type: "Point",
    coordinates: [location[0].longitude, location[0].latitude],
    formattedAddress: location[0].formattedAddress,
    street: location[0].streetName,
    city: location[0].city,
    state: location[0].stateCode,
    zipcode: location[0].zipcode,
    country: location[0].countryCode,
  };

  // Do not save address in db
  this.address = undefined;
  next();
});

// // Cascade Delete Courses When a Bootcamp is deleted
// BootcampSchema.pre("remove", async function(next) {
//   console.log("Courses Removed for", this._id);
//   await this.model("Course").deleteMany({ bootcamp: this._id });
//   next();
// });

module.exports = mongoose.model("Food", FoodSchema);
