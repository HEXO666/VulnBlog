require('dotenv').config(); // Load .env variables

const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');

// Use Atlas URI from .env
const MONGO_URI = process.env.MONGODB_URI;

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  author: String,
  slug: String,
  tags: [String],
  status: String,
  severity: String,
  imageUrl: String,
  excerpt: String,
  readTime: String,
  createdAt: Date,
  updatedAt: Date,
});

const Post = mongoose.model('Post', postSchema);

async function seed() {
  try {
    const mockPosts = JSON.parse(
      fs.readFileSync(path.join(__dirname, 'mockPosts.json'), 'utf-8')
    );

    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    await Post.deleteMany(); // Clear existing posts

    // Remove _id fields
    const postsToInsert = mockPosts.map(({ _id, ...rest }) => rest);

    await Post.insertMany(postsToInsert);
    console.log('✅ Mock posts inserted!');
  } catch (err) {
    console.error('❌ Seeding error:', err);
  } finally {
    await mongoose.disconnect();
  }
}

seed();
