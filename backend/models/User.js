import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  console.log(this.password)
  next();
});

userSchema.methods.comparePassword = function (password) {
  console.log(password)
  console.log(this.password)
  return bcrypt.compare(password, this.password);
};

export default mongoose.model('User', userSchema);