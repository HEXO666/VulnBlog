"use client"

import { useState } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { usePosts } from "./PostsContext"
import "./SinglePost.css"

function SinglePost() {
  const { slug } = useParams()
  const navigate = useNavigate()
  const { posts } = usePosts()
  const [showComments, setShowComments] = useState(false)

  const post = posts.find((p) => p.slug === slug)

  if (!post) {
    return (
      <div className="single-post-container">
        <div className="not-found">
          <div className="terminal-window">
            <div className="terminal-header">
              <div className="terminal-dot red"></div>
              <div className="terminal-dot yellow"></div>
              <div className="terminal-dot green"></div>
              <div className="terminal-title">404.sh</div>
            </div>
            <div className="terminal-content">
              <div className="terminal-line">
                <span className="terminal-prompt">$</span>
                <span className="terminal-text">find . -name "{slug}"</span>
              </div>
              <div className="terminal-line">
                <span className="terminal-text error">find: '{slug}': No such file or directory</span>
              </div>
              <div className="terminal-line">
                <span className="terminal-prompt">$</span>
                <span className="terminal-text">echo "Post not found"</span>
              </div>
              <div className="terminal-line">
                <span className="terminal-text">Post not found</span>
              </div>
            </div>
          </div>
          <button className="back-btn" onClick={() => navigate(-1)}>
            <span className="back-arrow">←</span> Return to Database
          </button>
        </div>
      </div>
    )
  }

  const formatContent = (content) => {
    return content
      .replace(/## (.*)/g, '<h2 class="post-heading">$1</h2>')
      .replace(/### (.*)/g, '<h3 class="post-subheading">$1</h3>')
      .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
      .replace(/\*(.*?)\*/g, "<em>$1</em>")
      .replace(/`(.*?)`/g, '<code class="inline-code">$1</code>')
      .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre class="code-block"><code>$2</code></pre>')
      .replace(/\n\n/g, '</p><p class="post-paragraph">')
      .replace(/\n/g, "<br>")
  }

  const getRelatedPosts = () => {
    return posts.filter((p) => p._id !== post._id && p.tags.some((tag) => post.tags.includes(tag))).slice(0, 3)
  }

  const relatedPosts = getRelatedPosts()

  return (
    <div className="single-post-container">
      {/* Navigation */}
      <div className="post-nav">
        <button className="back-btn" onClick={() => navigate(-1)}>
          <span className="back-arrow">←</span> Back to Exploits
        </button>
        <div className="post-nav-actions">
          <button className="nav-action-btn">
            <span>📋</span> Copy Link
          </button>
          <button className="nav-action-btn">
            <span>📤</span> Share
          </button>
          <button className="nav-action-btn">
            <span>⭐</span> Bookmark
          </button>
        </div>
      </div>

      {/* Hero Section */}
      <div className="post-hero">
        <div className="post-hero-content">
          <div className="post-meta-header">
            <div className={`severity-badge severity-${post.severity}`}>{post.severity?.toUpperCase()}</div>
            <div className="post-status">{post.status === "draft" ? "🚧 DRAFT" : "✅ PUBLISHED"}</div>
          </div>

          <h1 className="post-title">{post.title}</h1>

          <div className="post-meta">
            <div className="post-author">
              <div className="author-avatar">👤</div>
              <div className="author-info">
                <div className="author-name">@{post.author || "h4cker"}</div>
                <div className="author-title">Security Researcher</div>
              </div>
            </div>
            <div className="post-stats">
              <span className="post-date">{new Date(post.createdAt).toLocaleDateString()}</span>
              <span className="post-read-time">{post.readTime || "5 min read"}</span>
              <span className="post-views">1,337 views</span>
            </div>
          </div>

          <div className="post-tags">
            {post.tags.map((tag) => (
              <span key={tag} className="post-tag">
                #{tag}
              </span>
            ))}
          </div>
        </div>

        <div className="post-hero-image">
          <img src={post.imageUrl || "/placeholder.svg"} alt={post.title} />
        </div>
      </div>

      {/* Content Layout */}
      <div className="post-layout">
        <div className="post-content">
          <div className="post-body">
            <div
              className="post-text"
              dangerouslySetInnerHTML={{
                __html: `<p class="post-paragraph">${formatContent(post.content)}</p>`,
              }}
            />
          </div>

          {/* Comments Section */}
          <div className="post-comments">
            <div className="comments-header">
              <h3>Comments & Discussion</h3>
              <button className="toggle-comments-btn" onClick={() => setShowComments(!showComments)}>
                {showComments ? "Hide" : "Show"} Comments (42)
              </button>
            </div>

            {showComments && (
              <div className="comments-section">
                <div className="comment-form">
                  <div className="terminal-prompt">root@exploit:~$</div>
                  <textarea placeholder="Share your thoughts on this exploit..." className="comment-input" />
                  <button className="comment-submit">Post Comment</button>
                </div>

                <div className="comments-list">
                  <div className="comment">
                    <div className="comment-author">@n00b_hunter</div>
                    <div className="comment-text">
                      Great analysis! Tested this on my lab environment and confirmed the RCE. Thanks for the detailed
                      writeup.
                    </div>
                    <div className="comment-meta">2 hours ago • 👍 12</div>
                  </div>
                  <div className="comment">
                    <div className="comment-author">@sec_researcher</div>
                    <div className="comment-text">
                      Has anyone tried this against the latest version? Wondering if the patch is effective.
                    </div>
                    <div className="comment-meta">4 hours ago • 👍 8</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="post-sidebar">
          <div className="sidebar-section">
            <h4 className="sidebar-title">Exploit Info</h4>
            <div className="exploit-info">
              <div className="info-item">
                <span className="info-label">CVE ID:</span>
                <span className="info-value">{post.title.match(/CVE-\d{4}-\d+/)?.[0] || "N/A"}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Severity:</span>
                <span className={`info-value severity-${post.severity}`}>{post.severity?.toUpperCase()}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Published:</span>
                <span className="info-value">{new Date(post.createdAt).toLocaleDateString()}</span>
              </div>
              <div className="info-item">
                <span className="info-label">Updated:</span>
                <span className="info-value">{new Date(post.updatedAt || post.createdAt).toLocaleDateString()}</span>
              </div>
            </div>
          </div>

          <div className="sidebar-section">
            <h4 className="sidebar-title">Quick Actions</h4>
            <div className="quick-actions">
              <button className="action-btn">
                <span>📥</span> Download PoC
              </button>
              <button className="action-btn">
                <span>🔗</span> Copy Permalink
              </button>
              <button className="action-btn">
                <span>📊</span> View Analytics
              </button>
              <button className="action-btn">
                <span>🚨</span> Report Issue
              </button>
            </div>
          </div>

          {relatedPosts.length > 0 && (
            <div className="sidebar-section">
              <h4 className="sidebar-title">Related Exploits</h4>
              <div className="related-posts">
                {relatedPosts.map((relatedPost) => (
                  <div
                    key={relatedPost._id}
                    className="related-post"
                    onClick={() => navigate(`/post/${relatedPost.slug}`)}
                  >
                    <img
                      src={relatedPost.imageUrl || "/placeholder.svg"}
                      alt={relatedPost.title}
                      className="related-image"
                    />
                    <div className="related-content">
                      <h5 className="related-title">{relatedPost.title}</h5>
                      <div className="related-meta">
                        <span className={`related-severity severity-${relatedPost.severity}`}>
                          {relatedPost.severity?.toUpperCase()}
                        </span>
                        <span className="related-date">{new Date(relatedPost.createdAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default SinglePost
