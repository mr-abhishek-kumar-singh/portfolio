<style>
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  #matrix-terminal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background-color: #000;
    color: #00ff00;
    font-family: 'Courier New', monospace;
    font-size: 1rem;
    padding: 20px;
    z-index: 9999;
    overflow: hidden;
    display: flex;
    flex-direction: column-reverse;
    justify-content: flex-start;
    transition: opacity 2s ease;
  }

  .terminal-line {
    line-height: 1.4;
    white-space: pre;
    margin: 2px 0;
  }

  #portfolio {
    display: none; /* Hidden until terminal fades */
  }
</style>

<div id="matrix-terminal"></div>

<script>
fetch("https://ipapi.co/json/")
  .then(response => response.json())
  .then(data => {
    const browser = navigator.userAgent.split(") ")[0] + ")";
    const location = `${data.city}, ${data.region}, ${data.country_name}`;
    const ip = data.ip;

    const lines = [
      "[!] Confirming Identity:",
      `    - Origin: ${location}`,
      `    - IP fingerprint: ${ip}`,
      `    - Device: ${browser}`,
      "",
      "[!] Identity confirmed.",
      "Initializing website...",
    ];

    const terminal = document.getElementById("matrix-terminal");
    const portfolio = document.getElementById("portfolio");
    let currentLine = 0;

    function typeWriterLine(lineText, callback) {
      const line = document.createElement("div");
      line.className = "terminal-line";
      terminal.prepend(line);

      let charIndex = 0;
      function typeChar() {
        if (charIndex < lineText.length) {
          line.textContent += lineText.charAt(charIndex);
          charIndex++;
          setTimeout(typeChar, 30); // character typing speed
        } else {
          callback(); // move to next line
        }
      }

      typeChar();
    }

    function startTypingSequence() {
      if (currentLine < lines.length) {
        typeWriterLine(lines[currentLine], () => {
          currentLine++;
          setTimeout(startTypingSequence, 300); // time between lines
        });
      } else {
        // Done typing; begin fade out
        setTimeout(() => {
          terminal.style.opacity = 0;
          setTimeout(() => {
            terminal.style.display = "none";
            portfolio.style.display = "block";
          }, 2000); // match fade duration
        }, 3000); // wait before fade
      }
    }

    startTypingSequence();
  });
</script>
