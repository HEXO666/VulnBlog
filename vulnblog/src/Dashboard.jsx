"use client"

import { useState } from "react"
import { usePosts } from "./PostsContext"
import "./Dashboard.css"

function Dashboard() {
const { posts, createPost, updatePost, deletePost } = usePosts()
// const context = usePosts()
// const posts = context?.posts ?? []
// const createPost = context?.createPost
// const updatePost = context?.updatePost
// const deletePost = context?.deletePost

  const [editingId, setEditingId] = useState(null)
  const [editData, setEditData] = useState({})
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [activeTab, setActiveTab] = useState("posts")
  const [newPost, setNewPost] = useState({
    title: "",
    slug: "",
    content: "",
    tags: "",
    severity: "low",
    imageUrl: "",
    status: "published",
    excerpt: "",
  })

  const handleDelete = (id) => {
    if (window.confirm("Are you sure you want to delete this exploit?")) {
      deletePost(id)
    }
  }

  const handleEdit = (post) => {
    setEditingId(post._id)
    setEditData({ ...post, tags: Array.isArray(post.tags) ? post.tags.join(", ") : post.tags })
  }

  const handleEditChange = (e) => {
    setEditData({ ...editData, [e.target.name]: e.target.value })
  }

  const handleEditSave = () => {
    updatePost(editingId, { ...editData, tags: editData.tags.split(",").map((t) => t.trim()) })
    setEditingId(null)
    setEditData({})
  }

  const handleNewChange = (e) => {
    setNewPost({ ...newPost, [e.target.name]: e.target.value })
  }

  const handleCreate = (e) => {
    e.preventDefault()
    createPost({
      ...newPost,
      tags: newPost.tags.split(",").map((t) => t.trim()),
    })
    setNewPost({
      title: "",
      slug: "", 
      content: "",
      tags: "",
      severity: "low",
      imageUrl: "",
      status: "published",
      excerpt: "",
    })
    setShowCreateForm(false)
  }

  const getStats = () => {
    const total = posts.length
    const published = posts.filter((p) => p.status === "published").length
    const drafts = posts.filter((p) => p.status === "draft").length
    const critical = posts.filter((p) => p.severity === "critical").length
    return { total, published, drafts, critical }
  }

  const stats = getStats()

  return (
    <div className="dashboard-container">
      {/* Header */}
      <div className="dashboard-header">
        <div className="terminal-prompt">root@exploit-admin:~$</div>
        <h1 className="dashboard-title">EXPLOIT CONTROL PANEL</h1>
        <p className="dashboard-subtitle">Manage vulnerabilities and security research</p>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <div className="stat-number">{stats.total}</div>
            <div className="stat-label">Total Exploits</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">✅</div>
          <div className="stat-content">
            <div className="stat-number">{stats.published}</div>
            <div className="stat-label">Published</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🚧</div>
          <div className="stat-content">
            <div className="stat-number">{stats.drafts}</div>
            <div className="stat-label">Drafts</div>
          </div>
        </div>
        <div className="stat-card critical">
          <div className="stat-icon">🔥</div>
          <div className="stat-content">
            <div className="stat-number">{stats.critical}</div>
            <div className="stat-label">Critical</div>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="dashboard-tabs">
        <button className={`tab-btn ${activeTab === "posts" ? "active" : ""}`} onClick={() => setActiveTab("posts")}>
          <span>📝</span> Manage Posts
        </button>
        <button
          className={`tab-btn ${activeTab === "analytics" ? "active" : ""}`}
          onClick={() => setActiveTab("analytics")}
        >
          <span>📈</span> Analytics
        </button>
        <button
          className={`tab-btn ${activeTab === "settings" ? "active" : ""}`}
          onClick={() => setActiveTab("settings")}
        >
          <span>⚙️</span> Settings
        </button>
      </div>

      {/* Main Content */}
      {activeTab === "posts" && (
        <div className="dashboard-content">
          {/* Action Bar */}
          <div className="action-bar">
            <button className="create-btn" onClick={() => setShowCreateForm(!showCreateForm)}>
              <span>➕</span> {showCreateForm ? "Cancel" : "New Exploit"}
            </button>
            <div className="search-bar">
              <span className="search-prompt">$</span>
              <input className="search-input" placeholder="search exploits..." />
            </div>
          </div>

          {/* Create Form */}
          {showCreateForm && (
            <div className="create-form-container">
              <div className="form-header">
                <h3>Create New Exploit</h3>
                <div className="terminal-prompt">root@exploit:~$ nano new_exploit.md</div>
              </div>
              <form onSubmit={handleCreate} className="create-form">
                <div className="form-grid">
                  <div className="form-group">
                    <label>Title</label>
                    <input
                      name="title"
                      placeholder="CVE-YYYY-XXXX — Vulnerability Name"
                      value={newPost.title}
                      onChange={handleNewChange}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Slug</label>
                    <input
                      name="slug"
                      placeholder="cve-yyyy-xxxx-vulnerability-name"
                      value={newPost.slug}
                      onChange={handleNewChange}
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label>Tags</label>
                    <input
                      name="tags"
                      placeholder="CVE, RCE, PHP, Web"
                      value={newPost.tags}
                      onChange={handleNewChange}
                    />
                  </div>
                  <div className="form-group">
                    <label>Severity</label>
                    <select name="severity" value={newPost.severity} onChange={handleNewChange}>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Status</label>
                    <select name="status" value={newPost.status} onChange={handleNewChange}>
                      <option value="published">Published</option>
                      <option value="draft">Draft</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Image URL</label>
                    <input
                      name="imageUrl"
                      placeholder="https://placehold.co/500x300"
                      value={newPost.imageUrl}
                      onChange={handleNewChange}
                    />
                  </div>
                </div>
                <div className="form-group full-width">
                  <label>Excerpt</label>
                  <textarea
                    name="excerpt"
                    placeholder="Brief description of the vulnerability..."
                    value={newPost.excerpt}
                    onChange={handleNewChange}
                    rows={3}
                  />
                </div>
                <div className="form-group full-width">
                  <label>Content</label>
                  <textarea
                    name="content"
                    placeholder="## Overview&#10;&#10;Detailed vulnerability analysis...&#10;&#10;## Exploitation&#10;&#10;```bash&#10;# Exploit code here&#10;```"
                    value={newPost.content}
                    onChange={handleNewChange}
                    rows={10}
                  />
                </div>
                <div className="form-actions">
                  <button type="submit" className="submit-btn">
                    <span>💾</span> Create Exploit
                  </button>
                  <button type="button" className="cancel-btn" onClick={() => setShowCreateForm(false)}>
                    <span>❌</span> Cancel
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Posts Table */}
          <div className="posts-table-container">
            <div className="table-header">
              <h3>Exploit Database</h3>
              <div className="table-info">{posts.length} exploits found</div>
            </div>
            <div className="table-wrapper">
              <table className="posts-table">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Slug</th>
                    <th>Tags</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {posts.map((post) => (
                    <tr key={post._id} className={editingId === post._id ? "editing" : ""}>
                      {editingId === post._id ? (
                        <>
                          <td>
                            <input
                              name="title"
                              value={editData.title}
                              onChange={handleEditChange}
                              className="edit-input"
                            />
                          </td>
                          <td>
                            <input
                              name="slug"
                              value={editData.slug}
                              onChange={handleEditChange}
                              className="edit-input"
                            />
                          </td>
                          <td>
                            <input
                              name="tags"
                              value={editData.tags}
                              onChange={handleEditChange}
                              className="edit-input"
                            />
                          </td>
                          <td>
                            <select
                              name="severity"
                              value={editData.severity}
                              onChange={handleEditChange}
                              className="edit-select"
                            >
                              <option value="low">Low</option>
                              <option value="medium">Medium</option>
                              <option value="high">High</option>
                              <option value="critical">Critical</option>
                            </select>
                          </td>
                          <td>
                            <select
                              name="status"
                              value={editData.status}
                              onChange={handleEditChange}
                              className="edit-select"
                            >
                              <option value="published">Published</option>
                              <option value="draft">Draft</option>
                            </select>
                          </td>
                          <td>{new Date(post.createdAt).toLocaleDateString()}</td>
                          <td>
                            <div className="action-buttons">
                              <button onClick={handleEditSave} className="save-btn">
                                💾
                              </button>
                              <button onClick={() => setEditingId(null)} className="cancel-btn">
                                ❌
                              </button>
                            </div>
                          </td>
                        </>
                      ) : (
                        <>
                          <td>
                            <div className="post-title">{post.title}</div>
                          </td>
                          <td>
                            <code className="slug-code">{post.slug}</code>
                          </td>
                          <td>
                            <div className="tags-cell">
                              {(Array.isArray(post.tags) ? post.tags : []).slice(0, 3).map((tag) => (
                                <span key={tag} className="tag-mini">
                                  {tag}
                                </span>
                              ))}
                                {Array.isArray(post.tags) && post.tags.length > 3 && (
                                  <span className="tag-more">+{post.tags.length - 3}</span>
                                )}
                            </div>
                          </td>
                          <td>
                            <span className={`severity-badge severity-${post.severity}`}>
                              {post.severity?.toUpperCase()}
                            </span>
                          </td>
                          <td>
                            <span className={`status-badge status-${post.status}`}>
                              {post.status === "published" ? "✅" : "🚧"} {post.status?.toUpperCase()}
                            </span>
                          </td>
                          <td>{new Date(post.createdAt).toLocaleDateString()}</td>
                          <td>
                            <div className="action-buttons">
                              <button onClick={() => handleEdit(post)} className="edit-btn" title="Edit">
                                ✏️
                              </button>
                              <button onClick={() => handleDelete(post._id)} className="delete-btn" title="Delete">
                                🗑️
                              </button>
                            </div>
                          </td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === "analytics" && (
        <div className="dashboard-content">
          <div className="analytics-section">
            <h3>Analytics Dashboard</h3>
            <div className="analytics-grid">
              <div className="analytics-card">
                <h4>Severity Distribution</h4>
                <div className="severity-chart">
                  <div className="chart-bar critical" style={{ height: `${(stats.critical / stats.total) * 100}%` }}>
                    <span>{stats.critical}</span>
                  </div>
                  <div
                    className="chart-bar high"
                    style={{
                      height: `${(posts.filter((p) => p.severity === "high").length / stats.total) * 100}%`,
                    }}
                  >
                    <span>{posts.filter((p) => p.severity === "high").length}</span>
                  </div>
                  <div
                    className="chart-bar medium"
                    style={{
                      height: `${(posts.filter((p) => p.severity === "medium").length / stats.total) * 100}%`,
                    }}
                  >
                    <span>{posts.filter((p) => p.severity === "medium").length}</span>
                  </div>
                  <div
                    className="chart-bar low"
                    style={{
                      height: `${(posts.filter((p) => p.severity === "low").length / stats.total) * 100}%`,
                    }}
                  >
                    <span>{posts.filter((p) => p.severity === "low").length}</span>
                  </div>
                </div>
                <div className="chart-labels">
                  <span>Critical</span>
                  <span>High</span>
                  <span>Medium</span>
                  <span>Low</span>
                </div>
              </div>
              <div className="analytics-card">
                <h4>Recent Activity</h4>
                <div className="activity-list">
                  {posts
                    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
                    .slice(0, 5)
                    .map((post) => (
                      <div key={post._id} className="activity-item">
                        <div className="activity-icon">📝</div>
                        <div className="activity-content">
                          <div className="activity-title">{post.title}</div>
                          <div className="activity-date">{new Date(post.createdAt).toLocaleDateString()}</div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === "settings" && (
        <div className="dashboard-content">
          <div className="settings-section">
            <h3>System Configuration</h3>
            <div className="settings-grid">
              <div className="settings-card">
                <h4>Database Settings</h4>
                <div className="setting-item">
                  <label>Auto-backup</label>
                  <input type="checkbox" defaultChecked />
                </div>
                <div className="setting-item">
                  <label>Backup Interval</label>
                  <select>
                    <option>Daily</option>
                    <option>Weekly</option>
                    <option>Monthly</option>
                  </select>
                </div>
              </div>
              <div className="settings-card">
                <h4>Security Settings</h4>
                <div className="setting-item">
                  <label>Two-Factor Auth</label>
                  <input type="checkbox" />
                </div>
                <div className="setting-item">
                  <label>Session Timeout</label>
                  <select>
                    <option>30 minutes</option>
                    <option>1 hour</option>
                    <option>4 hours</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Dashboard
