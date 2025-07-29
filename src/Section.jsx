import './Section.css';

function Section() {
  return ( 
    <>
    <section className="hero">
        <div className="container">
            <div className="hero-content">
                <div className="hero-text">
                    <h2 className="hero-headline">
                        Documenting critical <span className="highlight">CVEs and RCEs</span> — fast, clear, and searchable.
                    </h2>
                    
                    <div className="cta-section">
                        <a href="#" className="cta-button">Browse Exploits</a>
                        <a href="#" className="cta-button secondary">Latest CVEs</a>
                    </div>
                </div>

                <div className="terminal-window">
                    <div className="terminal-header">
                        <div className="terminal-dot red"></div>
                        <div className="terminal-dot yellow"></div>
                        <div className="terminal-dot green"></div>
                        <div className="terminal-title">vulnblog.sh</div>
                    </div>
                    <div className="terminal-content">
                        <div className="terminal-line">
                            <span className="terminal-prompt-symbol">$</span>
                            <span className="terminal-text">echo "This helps:"</span>
                        </div>
                        <div className="terminal-line">
                            <span className="terminal-prompt-symbol">&gt;</span>
                            <span className="terminal-text highlight">Security researchers</span>
                        </div>
                        <div className="terminal-line">
                            <span className="terminal-prompt-symbol">&gt;</span>
                            <span className="terminal-text highlight">Bug bounty hunters</span>
                        </div>
                        <div className="terminal-line">
                            <span className="terminal-prompt-symbol">&gt;</span>
                            <span className="terminal-text highlight">Students studying exploitation</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div className="floating-elements">
            <div className="floating-code">CVE-2024-1337</div>
            <div className="floating-code">RCE_EXPLOIT.py</div>
            <div className="floating-code">#!/bin/bash</div>
        </div>
    </section>

    </>
  );
}

export default Section;
