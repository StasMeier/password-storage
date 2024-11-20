import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordFactory {

    public static PasswordFactory builder() {
        return new PasswordFactory();
    }

    public Password generate(Algorithm algorithm, String password) throws Exception {
        switch (algorithm) {
            case PBKDF2 -> {
                return createPBKDBFPassword(password, 600000, getSalt());
            }
            case MD5 -> {
                return createMD5Password(password, getSalt());
            }
        }
        return null;
    }

    public Password ofLine(String line) {
        if (line.startsWith(Algorithm.PBKDF2.name())) {
            List<String> l = List.of(line.split(","));
            return new PBKDBFPassword(l.get(3), l.get(2), Integer.valueOf(l.get(1)));
        }
        List<String> l = List.of(line.split(","));
        return new MD5Password(l.get(2), l.get(1));
    }

    public static Password createMD5Password(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hashValue = digest.digest((password + new String(salt)).getBytes(StandardCharsets.UTF_8));

        return new MD5Password(toHex(hashValue), toHex(salt));
    }

    public static Password createPBKDBFPassword(String password, int iterations, byte[] salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        char[] chars = password.toCharArray();

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

        byte[] hash = skf.generateSecret(spec).getEncoded();
        return new PBKDBFPassword(toHex(hash), toHex(salt), iterations);
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    private static String toHex(byte[] array) throws NoSuchAlgorithmException {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);

        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    static byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }



}
