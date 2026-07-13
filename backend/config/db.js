const mongoose = require('mongoose');

module.exports = async function connectDB() {
  const connection = await mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000,
  });
  console.log(`[database] Connected to ${connection.connection.host}`);
  return connection;
};
