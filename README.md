## 🛠️ VulnBlog — Fullstack Vulnerability Blog Platform

> A lightweight blog CMS for managing software vulnerabilities. Built with modern tooling, a bit of caffeine, and a sprinkle of sarcasm.

---

### 🚀 Overview

**VulnBlog** is a full-stack web application that allows users to manage blog posts about software vulnerabilities — including their severity, tags, and status (published/draft). Built for devs, testers, and anyone who appreciates a clean workflow.

---

### 👣 My Glorious Steps

1. **🧠 Step 1: Frontend First**

   * Built the full UI using **React + Vite** — because  the look before the logic.
   * Components, state management, routing, and all the fancy stuff were tackled before touching a single backend line.

2. **🧪 Step 2: Mocked It Like I Meant It**

   * Used **mock data** and static JSON APIs to simulate real backend responses.
   * Tested layout, logic, and data manipulation **without waiting on a server**. Fast prototyping = happy dev.

3. **🧱 Step 3: Backend Awakens**

   * Brought the backend to life with **Express** and **MongoDB**.
   * Set up a clean REST API with CRUD operations.
   * CORS was tamed, and sanity was preserved.

4. **🌱 Step 4: Seeder Squad**

   * Created a simple **data seeder script** to populate the database with vulnerability posts.
   * Because no one likes an empty blog — not even juries.

---

### 🧩 Tech Stack

| Layer     | Tech                                    |
| --------- | --------------------------------------- |
| Frontend  | React                                   |
| Backend   | Express.js                              |
| Database  | MongoDB (via Mongoose)                  |
| Styling   | CSS (i hate Bootstrap)                  |
| Dev Tools | Postman, console.log() therapy          |

---

### 📦 Installation

#### 1. Clone the project

```bash
git clone https://github.com/your-username/vulnblog
cd vulnblog
```

#### 2. Setup the Backend

```bash
cd backend
npm install
```

Create a `.env` file:

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/vulnblog
```

(Optional) Run the seeder:

```bash
node seeder.js
```

Start the server:

```bash
npm run dev
```

#### 3. Setup the Frontend

```bash
cd ../frontend
npm install
```

Create a `.env` file in `frontend/`:

```env
VITE_API_BASE_URL=http://localhost:5000
```

Then:

```bash
npm run dev
```

Now open your browser to `http://localhost:3000`

---

### 📚 Features

* 📰 Create, edit, delete vulnerability posts
* 📑 Slugs, tags, severity, image URLs, and excerpts
* 🟢 Status toggles between draft and published
* 🔍 Everything is filterable, sorted, and clean





---

### 🧹 To Do / Improvements

* Add authentication (JWT or session-based)
* File/image uploads
* Severity-based filtering or dashboard stats
* Dark mode (for your eyes and soul)

---

### 🤝 Credits

Built with ❤️ by HEXO

---
