-- ============================================================
-- vulnerable_app.sql
-- PL/SQL demo file with intentional SAST vulnerabilities
-- ============================================================

CREATE OR REPLACE PACKAGE vulnerable_app AS
    PROCEDURE main_proc(p_username IN VARCHAR2, p_filename IN VARCHAR2);
END vulnerable_app;
/

CREATE OR REPLACE PACKAGE BODY vulnerable_app AS

    -- SAST: Hardcoded credentials
    c_db_user     CONSTANT VARCHAR2(50)  := 'admin';
    c_db_pass     CONSTANT VARCHAR2(50)  := 'SuperSecret123!';
    c_secret_key  CONSTANT VARCHAR2(50)  := '1234567890abcdef';

    -- --------------------------------------------------------
    -- SAST: SQL Injection - dynamic SQL built via concatenation
    -- --------------------------------------------------------
    PROCEDURE query_user(p_username IN VARCHAR2) IS
        v_sql    VARCHAR2(1000);
        v_cursor SYS_REFCURSOR;
        v_name   VARCHAR2(100);
    BEGIN
        v_sql := 'SELECT username FROM users WHERE username = ''' || p_username || '''';
        -- Should use bind variable: USING p_username
        OPEN v_cursor FOR v_sql;
        LOOP
            FETCH v_cursor INTO v_name;
            EXIT WHEN v_cursor%NOTFOUND;
            DBMS_OUTPUT.PUT_LINE('User: ' || v_name);
        END LOOP;
        CLOSE v_cursor;
    END query_user;

    -- --------------------------------------------------------
    -- SAST: OS Command Injection via DBMS_SCHEDULER / host cmd
    -- --------------------------------------------------------
    PROCEDURE run_command(p_input IN VARCHAR2) IS
    BEGIN
        -- SAST: User input directly embedded into an OS job command
        DBMS_SCHEDULER.CREATE_JOB(
            job_name        => 'DYNAMIC_JOB',
            job_type        => 'EXECUTABLE',
            job_action      => '/bin/ls ' || p_input,   -- Command injection
            enabled         => TRUE,
            auto_drop       => TRUE
        );
    END run_command;

    -- --------------------------------------------------------
    -- SAST: Weak hashing - MD5 equivalent (DBMS_CRYPTO.HASH_MD5)
    -- --------------------------------------------------------
    PROCEDURE weak_hash(p_input IN VARCHAR2) IS
        v_hash RAW(16);
    BEGIN
        -- SAST: MD5 is cryptographically broken
        v_hash := DBMS_CRYPTO.HASH(
                      src  => UTL_I18N.STRING_TO_RAW(p_input, 'AL32UTF8'),
                      typ  => DBMS_CRYPTO.HASH_MD5
                  );
        DBMS_OUTPUT.PUT_LINE('Hash: ' || RAWTOHEX(v_hash));
    END weak_hash;

    -- --------------------------------------------------------
    -- SAST: Weak encryption - DES with hardcoded key
    -- --------------------------------------------------------
    PROCEDURE weak_encrypt(p_input IN VARCHAR2) IS
        v_key        RAW(8);
        v_encrypted  RAW(2000);
    BEGIN
        -- SAST: DES is deprecated; hardcoded key from package constant
        v_key       := UTL_I18N.STRING_TO_RAW(SUBSTR(c_secret_key, 1, 8), 'AL32UTF8');
        -- SAST: ENCRYPT_DES uses ECB mode by default - insecure
        v_encrypted := DBMS_CRYPTO.ENCRYPT(
                           src => UTL_I18N.STRING_TO_RAW(p_input, 'AL32UTF8'),
                           typ => DBMS_CRYPTO.ENCRYPT_DES + DBMS_CRYPTO.CHAIN_ECB + DBMS_CRYPTO.PAD_PKCS5,
                           key => v_key
                       );
        DBMS_OUTPUT.PUT_LINE('Encrypted: ' || RAWTOHEX(v_encrypted));
    END weak_encrypt;

    -- --------------------------------------------------------
    -- SAST: Insecure random number generation
    -- --------------------------------------------------------
    PROCEDURE insecure_token IS
        v_token NUMBER;
    BEGIN
        -- SAST: DBMS_RANDOM is not cryptographically secure
        v_token := TRUNC(DBMS_RANDOM.VALUE(0, 100000));
        DBMS_OUTPUT.PUT_LINE('Token: ' || v_token);
    END insecure_token;

    -- --------------------------------------------------------
    -- SAST: Path traversal - unsanitized filename in UTL_FILE
    -- --------------------------------------------------------
    PROCEDURE read_file(p_filename IN VARCHAR2) IS
        v_file   UTL_FILE.FILE_TYPE;
        v_line   VARCHAR2(32767);
    BEGIN
        -- SAST: p_filename not sanitized; allows directory traversal (../../etc/passwd)
        v_file := UTL_FILE.FOPEN('/app/data', p_filename, 'R');
        LOOP
            UTL_FILE.GET_LINE(v_file, v_line);
            DBMS_OUTPUT.PUT_LINE(v_line);
        END LOOP;
        -- SAST: Resource leak - file handle never closed on exception
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            UTL_FILE.FCLOSE(v_file);
        -- SAST: All other exceptions silently swallowed - no WHEN OTHERS handler
    END read_file;

    -- --------------------------------------------------------
    -- SAST: Empty exception handler - swallows all errors
    -- --------------------------------------------------------
    PROCEDURE risky_operation IS
    BEGIN
        -- Simulate a risky DB operation
        DELETE FROM audit_log WHERE log_date < SYSDATE - 365;
    EXCEPTION
        WHEN OTHERS THEN
            NULL; -- SAST: Silent failure; errors completely ignored
    END risky_operation;

    -- --------------------------------------------------------
    -- SAST: Possible NULL dereference - no NULL guard before use
    -- --------------------------------------------------------
    PROCEDURE null_deref_risk IS
        v_value VARCHAR2(100);
    BEGIN
        SELECT username INTO v_value
        FROM   users
        WHERE  ROWNUM = 1
        AND    1 = 0; -- Always returns no rows → v_value stays NULL

        -- SAST: No NULL check; LENGTH(NULL) returns NULL but further
        --       string operations on v_value will silently misbehave
        DBMS_OUTPUT.PUT_LINE('Length: ' || LENGTH(v_value));
        DBMS_OUTPUT.PUT_LINE('Upper: ' || UPPER(v_value));
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            NULL; -- SAST: Exception swallowed again
    END null_deref_risk;

    -- --------------------------------------------------------
    -- SAST: Privilege escalation - AUTHID CURRENT_USER missing;
    --       runs with DEFINER rights, granting excess privilege
    -- --------------------------------------------------------
    PROCEDURE elevated_query IS
        v_count NUMBER;
    BEGIN
        -- SAST: Executes as package owner (DBA), not calling user
        SELECT COUNT(*) INTO v_count FROM dba_users;
        DBMS_OUTPUT.PUT_LINE('Total DB users: ' || v_count);
    END elevated_query;

    -- --------------------------------------------------------
    -- Main entry point - orchestrates all vulnerable procedures
    -- --------------------------------------------------------
    PROCEDURE main_proc(p_username IN VARCHAR2, p_filename IN VARCHAR2) IS
    BEGIN
        query_user(p_username);
        run_command(p_username);
        weak_hash(p_username);
        weak_encrypt(p_username);
        insecure_token();
        read_file(p_filename);
        risky_operation();
        null_deref_risk();
        elevated_query();
    END main_proc;

END vulnerable_app;
/