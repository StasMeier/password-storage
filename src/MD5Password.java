import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class MD5Password implements Password {

    private String hashValue;
    private String salt;

    public MD5Password(String hashValue, String salt) {
        this.hashValue = hashValue;
        this.salt = salt;
    }

    public String getHashValue() {
        return hashValue;
    }

    public String getSalt() {
        return salt;
    }

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.MD5;
    }

    @Override
    public String toString() {
        return getAlgorithm() +  "," + salt + "," + hashValue;
    }

    @Override
    public boolean matches(String password) throws NoSuchAlgorithmException {
        return PasswordFactory.createMD5Password(password, PasswordFactory.fromHex(salt))
            .equals(this);
    }

    @Override
    public boolean isInsecure() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        MD5Password that = (MD5Password) o;
        return Objects.equals(hashValue, that.hashValue) && Objects.equals(salt, that.salt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(hashValue, salt);
    }
}
