import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface Password {

    Algorithm getAlgorithm();

    boolean matches(String password) throws NoSuchAlgorithmException, InvalidKeySpecException;

    boolean isInsecure();

}
