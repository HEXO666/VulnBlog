import './Section.css';

function Section() {
  return ( 
    <>
    <section class="hero">
        <div class="container">
            <div class="hero-content">
                <div class="hero-text">
                    <h2 class="hero-headline">
                        Documenting critical <span class="highlight">CVEs and RCEs</span> — fast, clear, and searchable.
                    </h2>
                    
                    <div class="cta-section">
                        <a href="#" class="cta-button">Browse Exploits</a>
                        <a href="#" class="cta-button secondary">Latest CVEs</a>
                    </div>
                </div>

                <div class="terminal-window">
                    <div class="terminal-header">
                        <div class="terminal-dot red"></div>
                        <div class="terminal-dot yellow"></div>
                        <div class="terminal-dot green"></div>
                        <div class="terminal-title">vulnblog.sh</div>
                    </div>
                    <div class="terminal-content">
                        <div class="terminal-line">
                            <span class="terminal-prompt-symbol">$</span>
                            <span class="terminal-text">echo "This helps:"</span>
                        </div>
                        <div class="terminal-line">
                            <span class="terminal-prompt-symbol">{'>'}</span>
                            <span class="terminal-text highlight">Security researchers</span>
                        </div>
                        <div class="terminal-line">
                            <span class="terminal-prompt-symbol">{'>'}</span>
                            <span class="terminal-text highlight">Bug bounty hunters</span>
                        </div>
                        <div class="terminal-line">
                            <span class="terminal-prompt-symbol">{'>'}</span>
                            <span class="terminal-text highlight">Students studying exploitation</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="floating-elements">
            <div class="floating-code">CVE-2024-1337</div>
            <div class="floating-code">RCE_EXPLOIT.py</div>
            <div class="floating-code">#!/bin/bash</div>
        </div>
    </section>

    </>
  );
}

export default Section;
