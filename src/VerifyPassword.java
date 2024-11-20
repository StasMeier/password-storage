import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class VerifyPassword {

    public static void main(String[] args)
        throws Exception {
        String originalPassword = args[0];

        List<Password> passwords = Files.readAllLines(Paths.get("psw.csv"))
            .stream()
            .map(line -> PasswordFactory.builder().ofLine(line))
            .toList();

        if(passwords.getFirst().isInsecure()) {
            System.err.println("Algorithm is not secure anymore. We use stronger hashing algorithm");

            String generatedSecuredPasswordHash
                = PasswordFactory.builder().generate(Algorithm.PBKDF2, originalPassword).toString();
            PrintWriter pw = new PrintWriter("psw.csv");
            pw.println(generatedSecuredPasswordHash);
            pw.close();
        }

        boolean matched = passwords.getFirst().matches(originalPassword);
        System.out.println(matched);
    }
}