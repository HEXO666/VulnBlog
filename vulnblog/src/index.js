import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';

import Header from './Header';
import Blog from './Blog';
import Section from './Section';
import SinglePost from './SinglePost';
import Dashboard from './Dashboard';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { PostsProvider } from './PostsContext';

function AppLayout() {
  const location = useLocation();
  const isDashboard = location.pathname === '/dashboard';

  return (
    <>
      <Header />
      {!isDashboard && <Section />}
      <Routes>
        <Route path="/" element={<Blog />} />
        <Route path="/post/:slug" element={<SinglePost />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <PostsProvider>
      <BrowserRouter>
        <AppLayout />
      </BrowserRouter>
    </PostsProvider>
  </React.StrictMode>
);
