import java.io.PrintWriter;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class CreatePassword {

    public static void main(String[] args)
        throws Exception {
        String originalPassword = args[0];

        Algorithm algorithm = Algorithm.valueOf(args[1]);

        String generatedSecuredPasswordHash
            = PasswordFactory.builder().generate(algorithm, originalPassword).toString();
        PrintWriter pw = new PrintWriter("psw.csv");
        pw.println(generatedSecuredPasswordHash);
        pw.close();
    }
}