import React, { useEffect, useState } from "react";
import "./Blog.css";
import { usePosts } from "./PostsContext";
import { useNavigate } from "react-router-dom";

const PAGE_SIZE = 6

const VulnBlog = () => {
  const [search, setSearch] = useState("")
  const [severity, setSeverity] = useState("all")
  const [tags, setTags] = useState([])
  const [filteredPosts, setFilteredPosts] = useState([])
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [viewMode, setViewMode] = useState("grid")


  const { posts } = usePosts();
const allTags = Array.from(
  new Set((Array.isArray(posts) ? posts : []).flatMap((p) => p.tags || []))
).sort();



  useEffect(() => {
    setLoading(true);
    setTimeout(() => {
      let filtered = [...posts];
      if (search) {
        const query = search.toLowerCase();
        filtered = filtered.filter(
          (post) =>
            post.title.toLowerCase().includes(query) ||
            (post.excerpt && post.excerpt.toLowerCase().includes(query)) ||
            post.tags.some((tag) => tag.toLowerCase().includes(query))
        );
      }
      if (severity !== "all") {
        filtered = filtered.filter((post) => post.severity === severity);
      }
      if (tags.length > 0) {
        filtered = filtered.filter((post) => tags.some((tag) => post.tags.includes(tag)));
      }
      setFilteredPosts(filtered);
      setPage(1);
      setLoading(false);
    }, 300);
  }, [search, severity, tags, posts]);

  const paginatedPosts = filteredPosts.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const toggleTag = (tag) => {
    setTags((prev) => (prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]))
  }


  const navigate = useNavigate();

  const renderListPost = (item, index) => (
    <div className="list-card" key={item._id}>
      <div className="list-image">
        <img src={item.imageUrl || "/placeholder.svg"} alt={item.title} />
        <div className={`severity-indicator severity-${item.severity}`}>{item.severity?.toUpperCase()}</div>
      </div>
      <div className="list-content">
        <div className="list-header">
          <div className="card-meta">
            <span className="author">@h4cker</span>
            <span>{new Date(item.createdAt).toLocaleDateString()}</span>
          </div>
          <div className="cve-badge">EXPLOIT</div>
        </div>
        <h3 className="list-title">{item.title}</h3>
        <p className="list-excerpt">{item.excerpt}</p>
        <div className="list-footer">
          <div className="card-tags">
            {item.tags.slice(0, 4).map((tag) => (
              <span key={tag} className="tag">
                #{tag}
              </span>
            ))}
            {item.tags.length > 4 && <span className="tag-more">+{item.tags.length - 4}</span>}
          </div>
          <button className="read-more-btn" onClick={() => navigate(`/post/${item.slug}`)}>
            Read More <span className="arrow">→</span>
          </button>
        </div>
      </div>
    </div>
  );


  const renderPost = (item, index) => (
    <div
      className={`blog-card ${index === 0 ? "featured" : ""} ${index % 7 === 0 && index !== 0 ? "wide" : ""}`}
      key={item._id}
    >
      <div className="card-image">
        <img src={item.imageUrl || "/placeholder.svg"} alt={item.title} />
        <div className={`severity-indicator severity-${item.severity}`}>{item.severity?.toUpperCase()}</div>
        {item.status === "draft" && <div className="draft-badge">DRAFT</div>}
      </div>
      <div className="card-content">
        <div className="card-meta">
          <span className="author">@h4cker</span>
          <span>{new Date(item.createdAt).toLocaleDateString()}</span>
        </div>
        <div className="cve-badge">EXPLOIT</div>
        <h3 className="card-title">{item.title}</h3>
        <p className="card-excerpt">{item.excerpt}</p>
        <div className="card-tags">
          {item.tags.slice(0, 3).map((tag) => (
            <span key={tag} className="tag">
              #{tag}
            </span>
          ))}
          {item.tags.length > 3 && <span className="tag-more">+{item.tags.length - 3}</span>}
        </div>
        <button className="read-more-btn" onClick={() => navigate(`/post/${item.slug}`)}>
          Read More <span className="arrow">→</span>
        </button>
      </div>
    </div>
  );

  return (
    <div className="container">
      <div className="blog-header">
        <div className="terminal-prompt">root@exploit:~$</div>
        <h1 className="blog-title">EXPLOIT DATABASE</h1>
        <p className="blog-subtitle">Latest vulnerabilities and proof-of-concepts</p>
      </div>

      <div className="filters-section">
        <div className="search-bar">
          <span className="search-prompt">$</span>
          <input
            className="search-input"
            placeholder="search exploits..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <div className="search-cursor"></div>
        </div>

        <div className="filter-row">
          <div className="filter-group">
            <div className="filter-label">
              <span>🔥</span> SEVERITY
            </div>
            <div className="filter-options">
              {["all", "critical", "high", "medium", "low"].map((level) => (
                <button
                  key={level}
                  className={`filter-btn ${severity === level ? "active" : ""}`}
                  onClick={() => setSeverity(level)}
                >
                  {level.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div className="filter-group">
            <div className="filter-label">
              <span>🏷️</span> TAGS
            </div>
            <div className="filter-options">
              {allTags.slice(0, 8).map((tag) => (
                <button
                  key={tag}
                  className={`tag-btn ${tags.includes(tag) ? "active" : ""}`}
                  onClick={() => toggleTag(tag)}
                >
                  #{tag}
                </button>
              ))}
              {tags.length > 0 && (
                <button className="clear-btn" onClick={() => setTags([])}>
                  Clear
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="results-header">
        <span className="results-count">{filteredPosts.length} exploits found</span>
        <div className="view-toggle">
          <button className={`view-btn ${viewMode === "grid" ? "active" : ""}`} onClick={() => setViewMode("grid")}>
            Grid
          </button>
          <button className={`view-btn ${viewMode === "list" ? "active" : ""}`} onClick={() => setViewMode("list")}>
            List
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading show">
          <div className="spinner"></div>
          Scanning for vulnerabilities...
        </div>
      ) : filteredPosts.length === 0 ? (
        <div className="no-results">
          <div className="terminal-window">
            <div className="terminal-header">
              <div className="terminal-dot red"></div>
              <div className="terminal-dot yellow"></div>
              <div className="terminal-dot green"></div>
              <div className="terminal-title">exploit.sh</div>
            </div>
            <div className="terminal-content">
              <div className="terminal-line">
                <span className="terminal-prompt">$</span>
                <span className="terminal-text">find . -name "*exploit*"</span>
              </div>
              <div className="terminal-line">
                <span className="terminal-text">No exploits found matching your criteria</span>
              </div>
              <div className="terminal-line">
                <span className="terminal-prompt">$</span>
                <span className="terminal-text">Try different search terms</span>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className={viewMode === "grid" ? "blog-grid" : "blog-list"}>
          {paginatedPosts.map(viewMode === "grid" ? renderPost : renderListPost)}
        </div>
      )}

      {filteredPosts.length > PAGE_SIZE && (
        <div className="pagination">
          <div className="pagination-info">
            <span>📊</span>
            Showing {(page - 1) * PAGE_SIZE + 1}-{Math.min(page * PAGE_SIZE, filteredPosts.length)} of{" "}
            {filteredPosts.length}
          </div>
          <div className="pagination-controls">
            <button className="pagination-btn" disabled={page === 1} onClick={() => setPage(page - 1)}>
              ← Previous
            </button>
            <div className="page-numbers">
              {Array.from({ length: Math.ceil(filteredPosts.length / PAGE_SIZE) }, (_, i) => i + 1)
                .filter((p) => p === 1 || p === Math.ceil(filteredPosts.length / PAGE_SIZE) || Math.abs(p - page) <= 1)
                .map((p, i, arr) => (
                  <React.Fragment key={p}>
                    {i > 0 && arr[i - 1] !== p - 1 && <span className="page-btn ellipsis">...</span>}
                    <button className={`page-btn ${page === p ? "active" : ""}`} onClick={() => setPage(p)}>
                      {p}
                    </button>
                  </React.Fragment>
                ))}
            </div>
            <button
              className="pagination-btn"
              disabled={page === Math.ceil(filteredPosts.length / PAGE_SIZE)}
              onClick={() => setPage(page + 1)}
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default VulnBlog
