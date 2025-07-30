
import React, { createContext, useContext, useState, useEffect } from "react";
const PostsContext = createContext();


export function PostsProvider({ children }) {
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);

  // Fetch posts from backend
 useEffect(() => {
  fetch("http://localhost:5000/api/posts")
    .then((res) => res.json())
    .then((data) => {
      console.log("API returned:", data); // Debug log
      if (Array.isArray(data)) {
  const sanitized = data.map((post) => ({
    ...post,
    tags: Array.isArray(post.tags) ? post.tags : [], // ensure tags is always an array
  }));
  setPosts(sanitized);
}
 else {
        console.warn("Invalid posts data:", data);
        setPosts([]); // fallback to empty array
      }
      setLoading(false);
    })
    .catch((err) => {
      console.error("Failed to fetch posts:", err);
      setPosts([]); // fallback
      setLoading(false);
    });
}, []);


  // Create post
 const createPost = async (post) => {
  console.log("Sending to backend:", post); 
  const res = await fetch("http://localhost:5000/api/posts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(post),
  });
  const newPost = await res.json();
  console.log("Received from backend:", newPost); 
  setPosts((prev) => [newPost, ...prev]);
};

  // Update post
  const updatePost = async (id, updated) => {
    const res = await fetch(`http://localhost:5000/api/posts/${id}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updated),
    });
    const updatedPost = await res.json();
    setPosts((prev) => prev.map((p) => (p._id === id ? updatedPost : p)));
  };

  // Delete post
  const deletePost = async (id) => {
    await fetch(`http://localhost:5000/api/posts/${id}`, { method: "DELETE" });
    setPosts((prev) => prev.filter((p) => p._id !== id));
  };

  return (
    <PostsContext.Provider value={{ posts, createPost, updatePost, deletePost, loading }}>
      {children}
    </PostsContext.Provider>
  );
}

export function usePosts() {
  return useContext(PostsContext);
}
