public class Login {
    public void authenticate(String user) {
        String query = "SELECT * FROM users WHERE name = " + user;
        // VULNERABLE: Concatenation
        statement.execute(query);
    }
}
