package laix.encryption;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger n, d, e;

    private int bitlen = 1024;

    public RSA(int bits) {
        bitlen = bits;
        SecureRandom r = new SecureRandom();
        //random p and q
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }

    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(e, n).toString();
    }

    public synchronized String decrypt(String message) {
        return new String((new BigInteger(message)).modPow(d, n).toByteArray());
    }

    public synchronized void generateKeys() {
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }

    public synchronized BigInteger getN() {
        return n;
    }

    public synchronized BigInteger getE() {
        return e;
    }

    public static void main(String[] args) {
        RSA rsa = new RSA(1024);

        String text1 = "test message";
        System.out.println("Plaintext: " + text1);

        String ciphertext = rsa.encrypt(text1);
        System.out.println("Ciphertext: " + ciphertext);
        String text2 = rsa.decrypt(ciphertext);

        System.out.println("Plaintext: " + text2);
    }
}
