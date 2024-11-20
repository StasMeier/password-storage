import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

public class PBKDBFPassword implements Password {

    private String hashValue;
    private String salt;
    private int iterations;

    public PBKDBFPassword(String hashValue, String salt, int iterations) {
        this.hashValue = hashValue;
        this.salt = salt;
        this.iterations = iterations;
    }

    public String getHashValue() {
        return hashValue;
    }

    public String getSalt() {
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.PBKDF2;
    }

    @Override
    public String toString() {
        return getAlgorithm() + "," + iterations + "," + salt + "," + hashValue;
    }

    @Override
    public boolean matches(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return PasswordFactory.createPBKDBFPassword(password, this.iterations, PasswordFactory.fromHex(salt))
            .equals(this);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        PBKDBFPassword that = (PBKDBFPassword) o;
        return iterations == that.iterations &&
            MessageDigest.isEqual(hashValue.getBytes(), that.hashValue.getBytes()) &&
            MessageDigest.isEqual(salt.getBytes(), that.salt.getBytes());
    }

    @Override
    public int hashCode() {
        return Objects.hash(hashValue, salt, iterations);
    }


    @Override
    public boolean isInsecure() {
        return false;
    }
}
