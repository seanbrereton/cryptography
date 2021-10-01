import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Random;
import java.security.NoSuchAlgorithmException;

public class DiffieHellman {
    public static void main(String[] args) {

        // prime modulus p
        BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        // generator g
        BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
        // Geoffs public shared value A
        BigInteger A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);
        // my private key b
        SecureRandom srand = new SecureRandom();
        BigInteger b = new BigInteger(1023, srand);
        // my public value B
        BigInteger B = modExponentiation(g, b, p);
        // shared secret s
        BigInteger s = modExponentiation(A, b, p);

        try {
            // generate secret key
            SecretKeySpec k = getSHAKey(s);

            // generate IV value
            SecureRandom rand = new SecureRandom();
            byte[] IV = new byte[16];
            rand.nextBytes(IV);
            IvParameterSpec iv = new IvParameterSpec(IV);

            // initialise cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, k, iv);

            // read file contents
            File file = new File(args[0]);
            FileInputStream input = new FileInputStream(file);
            // get file length and calculate padding needed
            int fileLen = (int)file.length();
            int paddingLength = 16 - (fileLen % 16);

            // create and pad plaintext byte array
            byte[] plainText = new byte[fileLen + paddingLength];
            plainText[plainText.length-paddingLength] = (byte) 128;

            // read plaintext and close
            input.read(plainText);
            input.close();

            // encrypt plain text and print to stadard output
            byte[] cipherText = cipher.doFinal(plainText);
            System.out.print(bytesToHex(cipherText));

            // print IV hex digit to IV.txt
            File ivOut = new File(System.getProperty("user.dir") + "/IV.txt");
            FileOutputStream ivStream = new FileOutputStream(ivOut);
            ivStream.write(bytesToHex(iv.getIV()).getBytes());
            ivStream.close();

            // print DH public key B to DH.txt
            File dh = new File(System.getProperty("user.dir") + "/DH.txt");
            FileOutputStream dhStream = new FileOutputStream(dh);
            dhStream.write(bytesToHex(B.toByteArray()).getBytes());
            dhStream.close();


        } catch (NoSuchAlgorithmException
                | InvalidKeyException
                | NoSuchPaddingException
                | InvalidAlgorithmParameterException
                | IOException
                | IllegalBlockSizeException
                | BadPaddingException e) {
            System.out.println(e);
        }
    }

    private static BigInteger modExponentiation(BigInteger base, BigInteger exponent, BigInteger mod) {

        // calculate left to right modular exponentiation
        BigInteger y = new BigInteger("1");
        for (int i = 0; i <= (exponent.bitLength() - 1); i++) {
            if (exponent.testBit(i)) {
                y = (y.multiply(base)).mod(mod);
            }
            base = (base.multiply(base)).mod(mod);
        }
        return y;
    }

    private static SecretKeySpec getSHAKey(BigInteger sharedS) throws NoSuchAlgorithmException {
        // calculate SHA-256 key from shared secret s
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] k = md.digest(sharedS.toByteArray());
        SecretKeySpec key = new SecretKeySpec(k, "AES");
        return key;
    }

    // taken from https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        // converts byte array to hex
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
