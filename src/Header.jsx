import './Header.css';

function Header() {
  return (
    <>
      <header className="header">
        <div className="container">
          <div className="header-content">
            <div className="logo-section">
              <h1 className="logo">VulnBlog</h1>
              <div className="terminal-prompt">root@vulnblog:~$ ./start_blog.sh</div>
              
            </div>

            <nav className="nav-container">
              <input type="checkbox" id="nav-toggle" className="nav-checkbox" />
              <label htmlFor="nav-toggle" className="nav-toggle">[MENU]</label>
              <ul className="nav">
                <li className="nav-item">
                  <a href="#" className="nav-link active">Home</a>
                </li>
                <li className="nav-item">
                  <a href="#" className="nav-link">Challenges</a>
                </li>
                <li className="nav-item">
                  <a href="#" className="nav-link">Writeups</a>
                </li>
                <li className="nav-item">
                  <a href="#" className="nav-link">Tools</a>
                </li>
              </ul>
            </nav>
          </div>
        </div>

      
      </header>
    </>
  );
}

export default Header;
