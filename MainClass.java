import java.sql.*;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class VulnerableApp {

    // SAST: Hardcoded credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "SuperSecret123!";

    // SAST: Hardcoded secret key
    private static final String SECRET_KEY = "1234567890abcdef";

    public static void main(String[] args) throws Exception {
        String userInput = args.length > 0 ? args[0] : "defaultUser";

        // SAST: SQL Injection - user input directly concatenated into query
        queryUser(userInput);

        // SAST: Command Injection - user input passed to Runtime.exec()
        runCommand(userInput);

        // SAST: Weak hashing algorithm (MD5)
        String hash = weakHash(userInput);
        System.out.println("Hash: " + hash);

        // SAST: Weak encryption (DES)
        byte[] encrypted = weakEncrypt(userInput);
        System.out.println("Encrypted: " + Arrays.toString(encrypted));

        // SAST: Insecure random number generation
        Random rand = new Random();
        int token = rand.nextInt(100000);
        System.out.println("Token: " + token);

        // SAST: Path traversal - unsanitized file path from user input
        readFile(userInput);

        // SAST: Catching generic Exception (bad practice, swallows errors)
        try {
            riskyOperation();
        } catch (Exception e) {
            // SAST: Empty catch block
        }

        // SAST: Null dereference risk - no null check before use
        String result = getValue();
        System.out.println(result.toUpperCase());
    }

    // SAST: SQL Injection
    private static void queryUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);
        while (rs.next()) {
            System.out.println("User: " + rs.getString("username"));
        }
    }

    // SAST: OS Command Injection
    private static void runCommand(String input) throws Exception {
        Runtime.getRuntime().exec("ls " + input);
    }

    // SAST: Weak hash (MD5)
    private static String weakHash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(digest);
    }

    // SAST: Weak encryption (DES)
    private static byte[] weakEncrypt(String input) throws Exception {
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.substring(0, 8).getBytes(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // SAST: ECB mode is insecure
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input.getBytes());
    }

    // SAST: Path traversal
    private static void readFile(String filename) throws Exception {
        FileReader fr = new FileReader("/app/data/" + filename);
        BufferedReader br = new BufferedReader(fr);
        String line;
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }
        // SAST: Resource leak - stream never closed
    }

    private static void riskyOperation() throws Exception {
        throw new Exception("Something went wrong");
    }

    // SAST: Always returns null, causing NullPointerException in caller
    private static String getValue() {
        return null;
    }
}