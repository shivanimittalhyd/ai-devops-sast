# Cline Code Review Runbook

## Purpose

This runbook instructs Cline to perform a structured, automated code review on Java and PL/SQL source files. It covers SAST findings, code quality issues, and best-practice violations, and produces a structured review report.

---

## Prerequisites

Before starting the review, confirm the following are available in the workspace:
- Source files to review (`.java`, `.sql`, `.pls`, or `.pkb`)
- This runbook loaded as Cline context or system prompt

---

## Step 1 — Discover Files

Scan the workspace for reviewable source files matching these patterns:
- `**/*.java`
- `**/*.sql`
- `**/*.pls`
- `**/*.pkb`

List all matched files with their relative paths. If more than 20 files are found, confirm with the user before proceeding.

---

## Step 2 — Per-File Review

For each file discovered in Step 1, perform the following checks in order.

### 2A — SAST Checks (Security)

Apply these checks to both Java and PL/SQL files unless noted otherwise.

**S1 — Hardcoded Credentials**
Look for passwords, API keys, or secret keys stored as constants or string literals in source code.
In Java, check for hardcoded strings assigned to variables like `password`, `secret`, `key`, or `token`.
In PL/SQL, check for CONSTANT declarations holding credential-like values.

**S2 — SQL Injection**
Look for dynamic queries assembled via string concatenation instead of parameterised statements.
In Java, flag any use of `Statement` with concatenated input; the fix is `PreparedStatement` with bind parameters.
In PL/SQL, flag any `EXECUTE IMMEDIATE` or `OPEN cursor FOR` that concatenates user input; the fix is the `USING` clause.

**S3 — Command Injection**
Look for unsanitised user input passed directly to OS execution APIs.
In Java, flag calls to `Runtime.getRuntime().exec()` or `ProcessBuilder` that include unvalidated input.
In PL/SQL, flag `DBMS_SCHEDULER` job actions that concatenate user input into the `job_action` parameter.

**S4 — Path Traversal**
Look for file paths constructed from user-supplied input without sanitisation.
In Java, flag `FileReader`, `FileInputStream`, or `File` constructors that concatenate user input.
In PL/SQL, flag `UTL_FILE.FOPEN` calls where the filename parameter is not validated or restricted to a known safe set.

**S5 — Weak Hashing**
Flag use of MD5 or SHA-1 for any security-sensitive purpose such as password storage or integrity checks.
In Java, flag `MessageDigest.getInstance("MD5")` or `MessageDigest.getInstance("SHA-1")`.
In PL/SQL, flag `DBMS_CRYPTO.HASH_MD5` or `DBMS_CRYPTO.HASH_SH1`.

**S6 — Weak Encryption**
Flag use of deprecated or insecure cipher algorithms and modes.
In Java, flag `Cipher.getInstance("DES/ECB/...")` or any DES/3DES usage.
In PL/SQL, flag `DBMS_CRYPTO.ENCRYPT_DES` and any use of `CHAIN_ECB`.

**S7 — Insecure Randomness**
Flag use of non-cryptographic random number generators for security-sensitive values such as tokens or session IDs.
In Java, flag `new java.util.Random()` and recommend `java.security.SecureRandom` instead.
In PL/SQL, flag `DBMS_RANDOM.VALUE` and recommend `DBMS_CRYPTO.RANDOMBYTES` instead.

**S8 — Definer-Rights Privilege Escalation (PL/SQL only)**
Flag any package, procedure, or function that accesses privileged objects such as DBA views or system tables but does not include `AUTHID CURRENT_USER` in its declaration.
Without this clause, the code executes with the owner's privileges rather than the caller's, potentially granting excess access.

**S9 — Sensitive Data in Logs**
Flag any logging statement that may output passwords, tokens, or personally identifiable information.
In Java, flag `System.out.println`, `System.err.println`, or logger calls that reference credential variables.
In PL/SQL, flag `DBMS_OUTPUT.PUT_LINE` calls that output sensitive variable values.

---

### 2B — Code Quality Checks

**Q1 — Empty Exception Handlers**
Flag exception handlers that silently swallow errors with no logging or re-raise.
In Java, flag `catch` blocks containing only a comment or nothing at all.
In PL/SQL, flag `WHEN OTHERS THEN NULL` with no logging or RAISE.

**Q2 — Overly Broad Exception Handling**
Flag catch clauses that catch the root exception type rather than specific, expected exceptions.
In Java, flag `catch (Exception e)` or `catch (Throwable t)`.
In PL/SQL, flag standalone `WHEN OTHERS` handlers that are the only exception clause.

**Q3 — Resource Leaks**
Flag resources that are opened but not guaranteed to be closed on all code paths including exception paths.
In Java, flag `Connection`, `Statement`, `ResultSet`, `FileReader`, `InputStream`, or `OutputStream` not wrapped in try-with-resources.
In PL/SQL, flag `SYS_REFCURSOR` or explicit cursors opened without a corresponding `CLOSE` in both the normal path and every exception handler.

**Q4 — Null Dereference Risk**
Flag variables that may be null or unset but are used without a prior null check.
In Java, flag method calls or field accesses on variables that could be null due to a failed query, optional return, or missing initialisation.
In PL/SQL, flag variables populated by `SELECT INTO` used after the statement without a `NO_DATA_FOUND` handler, or used inside an exception handler that silences `NO_DATA_FOUND`.

**Q5 — Dead Code**
Flag code that can never be executed.
Examples include unreachable branches after an unconditional return, conditions that are always true or always false, and declared variables that are never read.

**Q6 — Missing Input Validation**
Flag procedure or method parameters that are used in sensitive operations without any length, format, or allowlist check.
This overlaps with S2 through S4 but also covers non-security cases such as a numeric parameter used in arithmetic without a range check.

**Q7 — Magic Numbers and Strings**
Flag numeric or string literals used inline in logic that have no obvious self-documenting meaning and are not assigned to a named constant.

**Q8 — Unclosed Cursors (PL/SQL only)**
Flag `SYS_REFCURSOR` or explicit cursors that are opened in a procedure or function but have no `CLOSE` call on every exit path, including exception exits.

---

### 2C — Best Practice Checks

**B1 — Deprecated APIs (Java only)**
Flag use of `java.util.Date`, `java.sql.Date`, or `java.sql.Statement` where modern replacements exist.
Recommend `java.time.*` for date handling and `PreparedStatement` for all database queries.

**B2 — Hardcoded Connection Strings**
Flag JDBC URLs, database hostnames, ports, or schema names baked into source code.
These values should come from environment variables, configuration files, or a secrets manager.

**B3 — Missing Transaction Control**
In PL/SQL, flag DML statements (`INSERT`, `UPDATE`, `DELETE`) in procedures that have no explicit `COMMIT` or `ROLLBACK`, and no indication that the caller is expected to manage the transaction.
In Java, flag code that relies on autocommit for multi-statement operations that should be atomic.

**B4 — Non-Parameterised Dynamic SQL (PL/SQL only)**
Flag `EXECUTE IMMEDIATE` statements that build the SQL string via concatenation without using the `USING` clause for bind variables.

**B5 — Package-Level Mutable State (PL/SQL only)**
Flag package-level variables that are read or written during procedure execution.
These are session-global in Oracle and can cause unexpected behaviour in connection-pooled environments.

**B6 — Missing NOCOPY on Large IN OUT Parameters (PL/SQL only)**
Flag `IN OUT` parameters of type `VARCHAR2`, `CLOB`, `BLOB`, or collection types that do not use the `NOCOPY` hint, which forces unnecessary copying of large values.

---

## Step 3 — Severity Classification

Assign one of the following severity levels to every finding.

**CRITICAL**
An exploitable security vulnerability that could allow data exfiltration, unauthorised access, or remote code execution. Applies to SQL injection, command injection, hardcoded credentials, and path traversal.

**HIGH**
A security weakness that does not have a direct exploit path in isolation but significantly increases risk. Applies to weak hashing, weak encryption, privilege escalation, insecure randomness, and sensitive data in logs.

**MEDIUM**
A defect that could cause incorrect behaviour, data loss, or application instability under certain conditions. Applies to null dereference, resource leaks, empty exception handlers, and missing input validation.

**LOW**
A code quality issue with no immediate functional or security impact. Applies to magic numbers, dead code, missing NOCOPY hints, and minor style violations.

**INFO**
A best practice suggestion or observation with no current risk. Use this for findings that are context-dependent and may or may not require action.

---

## Step 4 — Generate Review Report

After completing checks on all files, produce a report using the structure below. Do not use tables or emoji in the report output.

```
# Code Review Report
Generated: <date>
Reviewed by: Cline

## Summary

Total findings: N
  Critical: N
  High: N
  Medium: N
  Low: N
  Info: N

---

## Findings

### Finding 1 — [CHECK-ID] [SEVERITY] — <Short Title>

File: path/to/file.java
Line: XX

Description:
<Explain what the issue is and why it is a problem.>

Vulnerable Code:
  <snippet of the problematic code>

Recommendation:
<Explain how to fix it. Include a corrected code example where possible.>

---

### Finding 2 — [CHECK-ID] [SEVERITY] — <Short Title>
(repeat for each finding)
```

---

## Step 5 — Prioritized Fix List

After the findings section, append a prioritised action list ordered from most to least severe.

```
## Prioritized Fix List

1. [S2] CRITICAL — SQL Injection in query_user
   Use PreparedStatement with bind parameters instead of string concatenation.

2. [S1] CRITICAL — Hardcoded DB password in package constants
   Move credentials to environment variables or a secrets manager.

3. [S3] CRITICAL — Command injection via Runtime.exec()
   Validate and whitelist all input before passing to OS execution APIs.

(continue for all findings)
```

---

## Step 6 — Output

Save the completed report as `code-review-report.md` in the root of the workspace, or in the directory specified by the user.

After saving, inform the user with a plain summary: "Code review complete. Report saved to code-review-report.md. N findings across M files."

---

## Cline Behaviour Rules

Do not modify any source file during the review unless the user explicitly asks for auto-fix mode.

Do not execute any source file. This is static analysis only.

If a file is too large to analyse in one pass, split it into logical sections such as individual methods or procedures, review each section fully, then move to the next.

If a finding is uncertain because the vulnerability depends on runtime context or calling code not visible in the current file, classify it as INFO and note the ambiguity clearly in the description.

Always include a Recommendation for every finding. Never flag an issue without providing actionable guidance.

When reviewing PL/SQL, treat the package specification and package body as a single unit. Read both before raising findings, as the spec may reveal intent that affects how the body is assessed.