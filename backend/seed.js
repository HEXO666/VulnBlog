const mongoose = require('mongoose');
const path = require('path');

const MONGO_URI = 'mongodb://localhost:27017/vulnblog';

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

const fs = require('fs');

async function seed() {
  const mockPosts = JSON.parse(fs.readFileSync(path.join(__dirname, 'mockPosts.json'), 'utf-8'));
  await mongoose.connect(MONGO_URI);
  await Post.deleteMany({}); // Clear existing posts
  // Remove _id from each post to let MongoDB generate it
  const postsToInsert = mockPosts.map(({ _id, ...rest }) => rest);
  await Post.insertMany(postsToInsert);
  console.log('Mock posts inserted!');
  await mongoose.disconnect();
}

seed().catch(console.error);
