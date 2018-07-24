package com.RNRSA;

import android.util.Log;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Random;

import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class RNRSADeterministicGenerator {

    public static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.abs().divide(b.gcd(a)).multiply(b.abs());
    }
    public static BigInteger sqrt(BigInteger n) {
        if (n.compareTo(BigInteger.ZERO) < 0) return null;

        int shift = 2;
        BigInteger shifted = n.shiftRight(shift);
        while (!shifted.equals(BigInteger.ZERO) && !shifted.equals(n)) {
            shift += 2;
            shifted = n.shiftRight(shift);
        }

        BigInteger result = BigInteger.ZERO;
        while (shift >= 0) {
            result = result.shiftLeft(1);
            BigInteger candidate = result.add(BigInteger.ONE);
            if (candidate.pow(2).compareTo(n.shiftRight(shift)) <= 0) {
                result = candidate;
            }
            shift -= 2;
        }
        return result;
    }
    private static class GeneratorState {
        public BigInteger d;
        public BigInteger n;
        public BigInteger e;
        public BigInteger p;
        public BigInteger q;
        public BigInteger min_p;
        public BigInteger min_q;
        public int size_p;
        public int size_q;
        public BigInteger min_distance;


        public GeneratorState(int bits, long eInt) {
            this.d = BigInteger.ONE;
            this.n = BigInteger.ONE;
            this.e = new BigInteger(Long.toString(eInt));
            this.p = null;
            this.q = null;

            this.size_q = bits / 2;
            this.size_p = bits - size_q;
            this.min_q = sqrt(BigInteger.ONE.shiftLeft(2*size_q-1));
            this.min_p = sqrt(BigInteger.ONE.shiftLeft(2*size_p-1));
            this.min_distance = BigInteger.ONE.shiftLeft(bits / 2 - 100);
        }

        public KeyPair toKeyPair() throws NoSuchAlgorithmException, InvalidKeySpecException {
            RSAPublicKeySpec pubspec = new RSAPublicKeySpec(this.n, this.e);
            RSAPrivateCrtKeySpec privspec = new RSAPrivateCrtKeySpec(this.n, this.e, this.d, this.p, this.q,
                    this.d.mod(this.p.subtract(BigInteger.ONE)),
                    this.d.mod(this.q.subtract(BigInteger.ONE)),
                    this.q.modInverse(this.p));

            KeyFactory f = KeyFactory.getInstance("EC");
            KeyPair pair = new KeyPair(f.generatePublic(pubspec), f.generatePrivate(privspec));
            RSAPublicKey rsaPublicKey = (RSAPublicKey) pair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) pair.getPrivate();
            boolean res = rsaPublicKey.getModulus().equals( rsaPrivateKey.getModulus() )
                    && BigInteger.valueOf( 2 ).modPow( rsaPublicKey.getPublicExponent()
                            .multiply( rsaPrivateKey.getPrivateExponent() ).subtract( BigInteger.ONE ),
                    rsaPublicKey.getModulus() ).equals( BigInteger.ONE );
            return pair;
        }
    }
    private static int getNumMillerRabinTests(int bits) {
        if(bits <= 100) return 27;
        if(bits <= 150) return 18;
        if(bits <= 200) return 15;
        if(bits <= 250) return 12;
        if(bits <= 300) return 9;
        if(bits <= 350) return 8;
        if(bits <= 400) return 7;
        if(bits <= 500) return 6;
        if(bits <= 600) return 5;
        if(bits <= 800) return 4;
        if(bits <= 1250) return 3;
        return 2;
    }

    private static boolean primeFilter(BigInteger candidate, GeneratorState state) {
        BigInteger minus_one = candidate.subtract(BigInteger.ONE);
        BigInteger min;
        boolean enoughDistance;

        if (state.p == null) {
            min = state.min_q;
            enoughDistance = true;
        } else {
            min = state.min_p;
            enoughDistance = (candidate.subtract(state.p).abs().compareTo(state.min_distance) > 0);
        }

        return (candidate.compareTo(min) > 0) &&
               (minus_one.gcd(state.e).compareTo(BigInteger.ONE) == 0) &&
               enoughDistance;
    }

    private static BigInteger generateProbablePrime(Random rng, GeneratorState state) {
        while (true) {
            int bits = (state.p == null) ? state.size_p : state.size_q;
            byte[] random = new byte[(bits+7)/8];
            rng.nextBytes(random);
            // hack to ensure that highest bit is unset so that bigint will think this number is
            // positive. We set it again below anyways
            random[0] &= 0x7F;
            random[random.length-1] |= 0x01;
            BigInteger candidate = new BigInteger(random);

            candidate = candidate.setBit(bits-1);
            if (primeFilter(candidate, state) &&
                    candidate.isProbablePrime(getNumMillerRabinTests(bits))) {
                return candidate;
            }
        }
    }

    public static KeyPair generateDeterministic(int bits, long eInt, byte[] seed) throws NoSuchAlgorithmException, InvalidKeySpecException{
        GeneratorState state = new GeneratorState(bits, eInt);
        Pbkdf2Rng rng = new Pbkdf2Rng(seed, bits);

        while (state.n.bitLength() != bits &&
                state.d.compareTo(BigInteger.ONE.shiftLeft(bits / 2)) < 0) {
            state.p = null;
            state.q = null;

            state.p = generateProbablePrime(rng, state);
            state.q = generateProbablePrime(rng, state);

            state.n = state.p.multiply(state.q);
            BigInteger _lcm = lcm(state.p.subtract(BigInteger.ONE), state.q.subtract(BigInteger.ONE));
            state.d = state.e.modInverse(_lcm);
        }

        if (state.p.compareTo(state.q) > 0) {
            BigInteger tmp = state.p;
            state.p = state.q;
            state.q = tmp;
        }

        return state.toKeyPair();
    }
}
