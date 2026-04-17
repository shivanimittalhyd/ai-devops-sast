# Code Review Report
Generated: 2026-04-17
Reviewed by: Cline

## Summary

Total findings: 21
  Critical: 8
  High: 7
  Medium: 6
  Low: 0
  Info: 0

---

## Findings

### Finding 1 — [S1] [CRITICAL] — Hardcoded database credentials in MainClass

File: MainClass.java
Line: 11-13

Description:
The database URL, username, and password are embedded as static final strings in the application. These credentials are exposed in source control and anyone with access to the repo can extract them, which could lead to unauthorised database access if the repository is compromised.

Vulnerable Code:
  private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
  private static final String DB_USER = "admin";
  private static final String DB_PASS = "SuperSecret123!";

Recommendation:
Move all sensitive configuration (DB URL, username, password) into an external configuration mechanism such as environment variables, encrypted configuration stores, or a secrets manager. Inject them at runtime instead of hardcoding.

---

### Finding 2 — [S2] [CRITICAL] — SQL injection in queryUser

File: MainClass.java
Line: 55-64

Description:
The SQL statement is built via string concatenation with user input and executed through a Statement object. Malicious input can break out of the quoted string and modify the query, leading to credential harvesting or data modification.

Vulnerable Code:
  Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
  Statement stmt = conn.createStatement();
  String query = "SELECT * FROM users WHERE username = '" + username + "'";

Recommendation:
Use PreparedStatement with bind variables instead of Statement concatenation. Example: 
```
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
stmt.setString(1, username);
```

---

### Finding 3 — [S3] [CRITICAL] — Command injection via Runtime.exec

File: MainClass.java
Line: 67-69

Description:
User input is appended to a shell command passed to Runtime.getRuntime().exec(). An attacker can inject shell metacharacters to execute arbitrary commands on the host.

Vulnerable Code:
  Runtime.getRuntime().exec("ls " + input);

Recommendation:
Avoid building shell commands with user input. If external programs must be invoked, validate/whitelist the input rigorously and prefer ProcessBuilder with argument lists so that user input cannot break out of the command shell.

---

### Finding 4 — [S4] [CRITICAL] — Path traversal from unsanitized filename

File: MainClass.java
Line: 86-94

Description:
The filename parameter provided by the user is concatenated into a filesystem path and used with FileReader. A specially crafted filename with '../' segments allows reading arbitrary files on the filesystem.

Vulnerable Code:
  FileReader fr = new FileReader("/app/data/" + filename);

Recommendation:
Restrict the filename to a safe set (e.g., allowlisting or canonical path validation) and avoid direct concatenation. Use java.nio.file.Path normalization and compare the resolved path against the intended base directory.

---

### Finding 5 — [S5] [HIGH] — Weak hashing with MD5

File: MainClass.java
Line: 71-75

Description:
MD5 is being used for hashing user input in a security-sensitive context. MD5 is considered broken and vulnerable to collisions.

Vulnerable Code:
  MessageDigest md = MessageDigest.getInstance("MD5");

Recommendation:
Use a modern hash algorithm such as SHA-256 (`MessageDigest.getInstance("SHA-256")`) or a password hashing function like PBKDF2/Bcrypt/Scrypt when storing credentials.

---

### Finding 6 — [S6] [HIGH] — Weak encryption using DES/ECB

File: MainClass.java
Line: 78-84

Description:
A DES cipher in ECB mode with a hardcoded key is used to encrypt user input. DES/ECB is outdated, insecure, and vulnerable to pattern leakage.

Vulnerable Code:
  Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

Recommendation:
Use AES in GCM or CBC mode with a securely generated key, and store the key outside of the source code. Prefer javax.crypto.SecretKey generated via KeyGenerator or derived via PBKDF2.

---

### Finding 7 — [S7] [HIGH] — Insecure randomness used for tokens

File: MainClass.java
Line: 35-38

Description:
java.util.Random is used to generate tokens. Random is not designed for cryptographic secrecy and can be predicted by attackers.

Vulnerable Code:
  Random rand = new Random();

Recommendation:
Use java.security.SecureRandom for any security-sensitive randomness.

---

### Finding 8 — [Q1/Q2] [MEDIUM] — Empty and overly broad exception handling

File: MainClass.java
Line: 43-48

Description:
The catch block catches Exception and contains no logging or rethrow, which swallows all errors silently and makes debugging impossible.

Vulnerable Code:
  try {
      riskyOperation();
  } catch (Exception e) {
      // empty
  }

Recommendation:
Catch specific exceptions, log the error, or rethrow it. At minimum propagate the exception or use a logging statement so that failures are visible.

---

### Finding 9 — [Q3] [MEDIUM] — Resource leak in readFile

File: MainClass.java
Line: 86-95

Description:
FileReader and BufferedReader are opened but never closed. If an exception occurs, the streams leak file descriptors.

Vulnerable Code:
  FileReader fr = new FileReader("/app/data/" + filename);
  BufferedReader br = new BufferedReader(fr);

Recommendation:
Wrap stream usage in try-with-resources to ensure they are always closed, even when exceptions occur.

---

### Finding 10 — [Q4] [MEDIUM] — Null dereference risk when calling getValue()

File: MainClass.java
Line: 50-53, 101-104

Description:
getValue() returns null and the caller immediately invokes toUpperCase(), which will throw NullPointerException.

Vulnerable Code:
  String result = getValue();
  System.out.println(result.toUpperCase());

Recommendation:
Ensure getValue() returns a non-null value or null-check before usage. Consider Optional<String> or default empty string when null is expected.

---

### Finding 11 — [S1] [CRITICAL] — Hardcoded credentials in PL/SQL package

File: DemoPLSQL.sql
Line: 13-16

Description:
Database credentials and secret keys are stored as package constants, exposing secrets to anyone who can read the source code.

Vulnerable Code:
  c_db_user     CONSTANT VARCHAR2(50)  := 'admin';
  c_db_pass     CONSTANT VARCHAR2(50)  := 'SuperSecret123!';
  c_secret_key  CONSTANT VARCHAR2(50)  := '1234567890abcdef';

Recommendation:
Move credentials out of the PL/SQL package. Use external credential stores or Oracle wallet and fetch values at runtime instead of hardcoding.

---

### Finding 12 — [S2] [CRITICAL] — SQL injection in query_user

File: DemoPLSQL.sql
Line: 21-35

Description:
Dynamic SQL concatenates p_username into the query string and executes it without bind variables. A malicious username can manipulate the SQL statement.

Vulnerable Code:
  v_sql := 'SELECT username FROM users WHERE username = ''' || p_username || '''';
  OPEN v_cursor FOR v_sql;

Recommendation:
Use bind variables with the USING clause when opening the cursor: `OPEN v_cursor FOR v_sql USING p_username;`.

---

### Finding 13 — [S3] [CRITICAL] — Command injection via DBMS_SCHEDULER job

File: DemoPLSQL.sql
Line: 40-50

Description:
The job_action parameter concatenates user input into a shell command, which can be manipulated to run arbitrary OS commands.

Vulnerable Code:
  job_action      => '/bin/ls ' || p_input,

Recommendation:
Do not embed user-supplied text directly into job_action. Validate or whitelist filenames, or avoid shell commands altogether.

---

### Finding 14 — [S5] [HIGH] — Weak hashing with DBMS_CRYPTO.HASH_MD5

File: DemoPLSQL.sql
Line: 55-64

Description:
MD5 is used for hashing, which is vulnerable to collisions and unsuitable for security contexts.

Vulnerable Code:
  typ  => DBMS_CRYPTO.HASH_MD5

Recommendation:
Use a stronger algorithm like `DBMS_CRYPTO.HASH_SH256` and avoid MD5 for integrity or authentication.

---

### Finding 15 — [S6] [HIGH] — DES/ECB encryption with hardcoded key

File: DemoPLSQL.sql
Line: 69-82

Description:
DES in ECB mode with a hardcoded key is used, which leaks structure and is deprecated.

Vulnerable Code:
  typ => DBMS_CRYPTO.ENCRYPT_DES + DBMS_CRYPTO.CHAIN_ECB

Recommendation:
Move to AES (e.g., `DBMS_CRYPTO.ENCRYPT_AES128`) in CBC/GCM mode with a key stored outside the code.

---

### Finding 16 — [S7] [HIGH] — Non-cryptographic randomness

File: DemoPLSQL.sql
Line: 87-93

Description:
DBMS_RANDOM.VALUE is used to generate tokens. It is not designed for cryptographic randomness and is predictable.

Vulnerable Code:
  v_token := TRUNC(DBMS_RANDOM.VALUE(0, 100000));

Recommendation:
Use `DBMS_CRYPTO.RANDOMBYTES` for cryptographically secure random values.

---

### Finding 17 — [S4] [CRITICAL] — Path traversal via UTL_FILE.FOPEN

File: DemoPLSQL.sql
Line: 98-113

Description:
The filename parameter is used directly with UTL_FILE.FOPEN, allowing directory traversal attacks that can read arbitrary files.

Vulnerable Code:
  v_file := UTL_FILE.FOPEN('/app/data', p_filename, 'R');

Recommendation:
Validate the filename against an allow list or canonicalize and ensure it stays within the intended directory before opening the file.

---

### Finding 18 — [Q3] [MEDIUM] — File handle not closed on errors

File: DemoPLSQL.sql
Line: 98-113

Description:
UTL_FILE.FOPEN is called but the handle is not closed if an exception other than NO_DATA_FOUND occurs, causing resource leaks.

Vulnerable Code:
  UTL_FILE.GET_LINE(v_file, v_line);

Recommendation:
Close the handle in a WHEN OTHERS or USE sections ensuring it executes regardless of success/failure.

---

### Finding 19 — [Q1] [MEDIUM] — Empty exception handler in risky_operation

File: DemoPLSQL.sql
Line: 118-125

Description:
The procedure swallows all errors with `WHEN OTHERS THEN NULL`, making failures invisible and hiding operational issues.

Vulnerable Code:
  EXCEPTION
      WHEN OTHERS THEN
          NULL;

Recommendation:
Log or re-raise the exception. At a minimum, raise an application error or insert into an audit log so that errors are visible.

---

### Finding 20 — [Q4] [MEDIUM] — Null dereference risk and silent errors

File: DemoPLSQL.sql
Line: 130-145

Description:
The SELECT INTO always returns no rows, leaving v_value NULL. Subsequent calls to LENGTH and UPPER operate on NULL and return NULL or throw NO_DATA_FOUND, which is silently ignored.

Vulnerable Code:
  SELECT username INTO v_value ... AND 1 = 0;

Recommendation:
Handle NO_DATA_FOUND properly or guard further logic when null is expected. Do not suppress the exception without corrective action.

---

### Finding 21 — [S8] [HIGH] — Package runs with DEFINER rights

File: DemoPLSQL.sql
Line: 148-157

Description:
The package body lacks `AUTHID CURRENT_USER`, so all procedures execute with the package owner’s privileges, which can be excessive if the owner is a privileged account.

Vulnerable Code:
  PACKAGE BODY vulnerable_app AS

Recommendation:
Add `AUTHID CURRENT_USER` to the package header so execution uses the caller’s privileges and reduces the risk of privilege escalation.

---

## Prioritized Fix List

1. [S2] CRITICAL — SQL injection in query_user
   Use bind variables with the USING clause to avoid concatenating user input into dynamic SQL.

2. [S3] CRITICAL — Command injection via DBMS_SCHEDULER job
   Do not inline user input inside job_action; validate/whitelist or avoid shell commands.

3. [S4] CRITICAL — Path traversal via UTL_FILE.FOPEN
   Restrict filenames to known-safe values and validate the resolved path before opening files.

4. [S1] CRITICAL — Hardcoded credentials in MainClass and PL/SQL package
   Move all secrets to secure configuration sources rather than embedding them in code.

5. [S3] CRITICAL — Command injection via Runtime.exec
   Avoid shell commands with user input; use argument lists or secure validation.

6. [S4] CRITICAL — Path traversal in MainClass readFile
   Normalize paths and enforce allow lists before accessing files.

7. [S5/S6/S7/S8] HIGH — Weak cryptography/randomness and privilege escalation
   Replace MD5/DES/Random with modern alternatives and add AUTHID CURRENT_USER.

8. [Q1/Q3/Q4] MEDIUM — Resource leaks, null dereferences, and silent exception handling
   Introduce try-with-resources or proper exception handling, close resources on all paths, and validate null usage.