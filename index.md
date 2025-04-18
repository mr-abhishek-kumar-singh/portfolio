## About Me
I am a cybersecurity professional and automation engineer with a strong background in penetration testing, security automation, and cloud security. With hands-on experience in ethical hacking, network security, and automation, I am passionate about securing digital assets and streamlining security processes through scripting and automation. 


## Skills
- **Penetration Testing**: Web applications, APIs, Mobile apps, Network infrastructure
- **Security Automation**: Custom security tools, Python scripting, Automation frameworks
- **Cloud Security**: Google Cloud security, DevOps security practices
- **Networking**: CCNA concepts, Network analysis, Firewall configurations
- **Programming**: Python, Bash scripting, PowerShell
- **Operating Systems**: Linux (RedHat, Debian-based), Windows security configurations
- **Tools & Technologies**: Scapy, Burp Suite, Metasploit, Nmap, BloodHound, Wireshark, GoBuster, SMBMap, WPScan


## Accomplishments
- Successfully performed penetration testing on various services at **SRM Delhi**, **Glida, Radius, and Ez-Swype**.
- Developed security assessment methodologies for organizations to enhance their security posture.
- Currently building a **security assessment tool** for organizations to identify website vulnerabilities.
- Completed multiple security certifications to solidify expertise in ethical hacking and automation.


## Certifications
While certifications, for some people, are just a piece of paper that proves that you can type some stuff into the computer and click some buttons, but they also play a crucial role in determining what and when to click. So here are some of my button clicks that taught me highly valuable information regarding how to hack various things:
- **Offensive Security**:
  - CEHv12 & CEH Practical
  - Certified in Cybersecurity by ISC2
  - eJPTv2 by INE Security
  - OSCP *(Soon...)*
- **Scripting & Application Security**:
  - Practical Ethical Hacking (PEH)
  - Mobile Application Penetration Tester (MAPT)
  - Practical Bug Bounty Hunter
  - Programming with AI - Mini Course
  - Linux 100 & 101
  - Python 101 & 201
  - Programming 100
- **Networking and Cloud Security**:
  - Google Cybersecurity Certification
  - Google Cloud Certification - Cloud DevOps Engineer
- **Soft Skills for Job Market**
  - Soft Skills for Cyber Security Job Market  

## Projects
- [Recon-Sub](https://github.com/mr-abhishek-kumar-singh/recon-sub): Automated subdomain enumeration tool for reconnaissance.
- [SSL Certificate Checker](https://github.com/mr-abhishek-kumar-singh/ssl-certificate-checker): A Python tool to check SSL certificate validity and expiration.
- [Scapy Port Enum](https://github.com/mr-abhishek-kumar-singh/scapy-port-enum): A network enumeration tool using Scapy for scanning open ports.
- [CSRF Token Bypass Script](https://github.com/mr-abhishek-kumar-singh/csrf-token-bypass-script): A Python script to test CSRF token vulnerabilities in web applications.
- [Web Login BF](https://github.com/mr-abhishek-kumar-singh/web-login-bf): A brute force tool to test login authentication security on web applications.
- [SHA256 Crack](https://github.com/mr-abhishek-kumar-singh/sha256-crack): A Python-based SHA256 hash cracker for security testing.
- MantraCrawler: _Coming soon..._


## Interests
- Ethical hacking and red teaming methodologies
- Security automation and AI-driven security solutions
- Open-source contributions in cybersecurity and automation
- Financial investment strategies and wealth management
- Gaming and content creation
- Book reading


## Contact
- [LinkedIn](https://www.linkedin.com/in/mr-abhishek-kumar-singh)
- [GitHub](https://github.com/mr-abhishek-kumar-singh)
- [Email](mailto:abhishekkrsingh.infosec@gmail.com)
- [Website](https://mr-abhishek-kumar-singh.github.io/portfolio/)


## A bit about the Hacker's Realm

> **Fun fact**: The word "hacker" was first used in 1970s by members of the MIT to describe attackers who would illegally bypass security measures gaining access to data and software.

Hackers are everywhere! In today's world, we all use "hacks" or "tricks" to get the job done. Be it using your brain, or leveraging a tool to find clever ways to get something done. Hacking has been a part of human lives way before the term was coined.

The question arises - What exactly is data and softwares and why do we need to protect them?

Data is any information that holds value, be it your cutesy family photos, or your documents you store on Cloud Drives, data exists everywhere. Before internet was even a thing, there were printed documents that needed to be secured to prevent unwanted access or tampering. On the other hand, softwares are a set of instructions, data, or programs that tell a computer what to do and how to do it, enabling it to perform specific tasks and interact with users. Both data and softwares go hand-in-hand to perform the so-called information exchange. 

So, protecting the data using various techniques is similar to those scanners and security guards you encounter in mall entrances. Data and softwares need to be protected from **Cyber attacks**, requiring both checking and verification.

In case you are wondering how cyber attacks work, the friendly little pop-up when you clicked the link was a harmless example of an XSS attack, which can be used to steal your information or inject a virus into your system.

Many more such attacks exist in the real world. While it is practically impossible to be completely secure in this ever-evolving world, my objective is to contribute to the safety of the internet.

On that note, I thank you for visitng my portfolio. Happy hacking!

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
