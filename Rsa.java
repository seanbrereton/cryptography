import java.io.*;
import java.math.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import java.util.BitSet;
import java.util.Random;

// CRT implementation uses info from https://crypto.stackexchange.com/questions/2575/chinese-remainder-theorem-and-rsa
public class Rsa {

    public static void main(String[] args) {
        // public/private RSA key pair
        //probable primes p and q

        BigInteger p;
        BigInteger q;
        BigInteger n;
        BigInteger phi;
        BigInteger[] values;

        // encryption exponent e
        BigInteger e = new BigInteger("65537");

        do {
            p = BigInteger.probablePrime(512, new Random());
            q = BigInteger.probablePrime(512, new Random());

            // product of pq
            n = p.multiply(q);

            // euler totient of n
            phi = eulerTotient(p, q);

            // value for private decryption key d
            values = extEuclidianGCD(phi, e);
        } while (!(values[0].equals(BigInteger.ONE)));

        // decryption exponent
        BigInteger d;
        // if inv is less than 0 add it to phi
        if (values[2].compareTo(new BigInteger("0")) == -1) {
            d = values[2].add(phi);
        } else {
            d = values[2];
        }

        try {

            // create SHA-256 message digest from input file
            String file = args[0];
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            BigInteger  md = new BigInteger(1, digest.digest(Files.readAllBytes(Paths.get(file))));

            // create signed digest using decryption function and print to standard output
            BigInteger signature = decryption(d, md, p, q);
            System.out.print(signature.toString(16));

            // print modulus n to 'Modulus.txt'
            File nOut = new File(System.getProperty("user.dir") + "/Modulus.txt");
            FileOutputStream nStream = new FileOutputStream(nOut);
            nStream.write(n.toString(16).getBytes());
            nStream.close();

        } catch(Exception err) {
            System.out.print(err);
        }

    }

    private static BigInteger eulerTotient(BigInteger p, BigInteger q) {
        BigInteger one = new BigInteger("1");
        // if p and q are equal p or q is the gcd
        if (p.equals(q)) {
            return p;
        } else {
            // because p and q are prime phi(n) = (p-1)(q-1)
            p = p.subtract(one);
            q = q.subtract(one);
            return p.multiply(q);
        }
    }

    private static BigInteger[] extEuclidianGCD(BigInteger a, BigInteger b) {
        // implementation of the extended Euclidian GCD algorithm
        // base case where b == 0
        if (b.equals(new BigInteger("0"))) {
            BigInteger s = new BigInteger("1");
            BigInteger t = new BigInteger("0");
            // return bigInt array with gcd as a, coefficient of a as s, and coeffeicient of b as t
            return new BigInteger[] {a, s, t};
        }

        // call gcd func with b as a ,and a mod b as b
        BigInteger[] tmp = extEuclidianGCD(b, a.mod(b));
        BigInteger gcd = tmp[0];
        // s and t coefficient
        BigInteger s = tmp[2];
        BigInteger t = tmp[1].subtract((a.divide(b)).multiply(tmp[2]));
        return new BigInteger[] {gcd, s, t};

    }

    private static BigInteger crt(BigInteger mq, BigInteger mp, BigInteger q, BigInteger invQ, BigInteger p) {
        // calculate Chinese Remainder theorem
        BigInteger crtVal;
        crtVal = mq.add(q.multiply((invQ.multiply(mp.subtract(mq))).mod(p)));
        return crtVal;
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

    private static BigInteger decryption(BigInteger d, BigInteger digest, BigInteger p, BigInteger q) {
        // calculate mod exp of p and q
        BigInteger mulP = modExponentiation(digest, d.mod(p.subtract(BigInteger.ONE)), p);
        BigInteger mulQ = modExponentiation(digest, d.mod(p.subtract(BigInteger.ONE)), q);

        // mul inv of q mod
        BigInteger[] x = extEuclidianGCD(q, p);
        BigInteger invQ = x[2];

        BigInteger crtVal = crt(mulQ, mulP, q, invQ, p);
        return crtVal;
    }
}
