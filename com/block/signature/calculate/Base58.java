package com.block.signature.calculate;

import com.block.signature.struct.Triple;

import java.math.BigInteger;

public class Base58 {

    public static final String digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static String encode(byte[] b) {
        StringBuilder sb = new StringBuilder();
        BigInteger n = Binint.b2n(b);
        BigInteger base = BigInteger.valueOf(digits.length());
        while (n.compareTo(BigInteger.ZERO) > 0) {
            BigInteger r = n.mod(base);
            n = n.divide(base);
            sb.append(digits.charAt(r.intValue()));
        }
        for (byte c : b) {
            if (c != 0) break;
            sb.append(digits.charAt(0));
        }
        return sb.reverse().toString();
    }

    public static byte[] decode(String w) {
        BigInteger v = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(digits.length());
        for (int i = 0; i < w.length(); i++) {
            char c = w.charAt(i);
            int index = digits.indexOf(c);
            if (index < 0) throw new IllegalArgumentException("Invalid input");
            v = v.multiply(base).add(BigInteger.valueOf(index));
        }
        byte[] b = Binint.n2b(v);
        int zeros = 0;
        for (int i = 0; i < w.length(); i++) {
            char c = w.charAt(i);
            if (c != digits.charAt(0)) break;
            zeros++;
        }
        if (zeros > 0) {
            byte[] t = new byte[zeros + b.length];
            System.arraycopy(b, 0, t, zeros, b.length);
            b = t;
        }
        return b;
    }

    public static String check_encode(byte[] b) {
        return check_encode(b, new byte[]{}, new byte[]{});
    }

    public static String check_encode(byte[] b, byte[] prefix, byte[] suffix) {
        return check_encode(b, prefix, suffix, null);
    }

    public static String check_encode(byte[] b, byte[] prefix, byte[] suffix, Hashing.hashfun f) {
        if (f == null) f = Base58::_sub_hash256_0_4;
        b = Bytes.concat(prefix, b, suffix);
        byte[] h = f.hash(b);
        b = Bytes.concat(b, h);
        return encode(b);
    }

    public static Triple<byte[], byte[], byte[]> check_decode(String w) {
        return check_decode(w, 0, 0);
    }

    public static Triple<byte[], byte[], byte[]> check_decode(String w, int prefix_len, int suffix_len) {
        return check_decode(w, prefix_len, suffix_len, 4, null);
    }

    public static Triple<byte[], byte[], byte[]> check_decode(String w, int prefix_len, int suffix_len, int hash_len, Hashing.hashfun f) {
        if (f == null) f = Base58::_sub_hash256_0_4;
        byte[] b = decode(w);
        if (b.length < prefix_len + hash_len) throw new IllegalArgumentException("Invalid length");
        if (hash_len == 0) hash_len = -b.length;
        byte[] h = Bytes.sub(b, -hash_len);
        b = Bytes.sub(b, 0, -hash_len);
        if (!Bytes.equ(h, f.hash(b))) throw new IllegalArgumentException("Invalid hash");
        byte[] prefix = Bytes.sub(b, 0, prefix_len);
        b = Bytes.sub(b, prefix_len);
        if (suffix_len == 0) suffix_len = -b.length;
        byte[] suffix = Bytes.sub(b, -suffix_len);
        b = Bytes.sub(b, 0, -suffix_len);
        return new Triple<>(b, prefix, suffix);
    }

    public static String translate(String w, String from_digits, String to_digits) {
        if (from_digits == null) from_digits = digits;
        if (to_digits == null) to_digits = digits;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < w.length(); i++) {
            char c = w.charAt(i);
            int index = from_digits.indexOf(c);
            if (index < 0) throw new IllegalArgumentException("Invalid input");
            sb.append(to_digits.charAt(index));
        }
        return sb.toString();
    }

    public static byte[] _sub_hash256_0_4(byte[] b) {
        return Bytes.sub(Hashing.hash256(b), 0, 4);
    }

    public static byte[] _sub_ripemd160_0_4(byte[] b) {
        return Bytes.sub(Hashing.ripemd160(b), 0, 4);
    }

    public static byte[] _sub_blake1s_0_4(byte[] b) {
        return Bytes.sub(Hashing.blake1s(b), 0, 4);
    }

    public static byte[] _sub_blake256_0_4(byte[] b) {
        return Bytes.sub(Hashing.blake256(b), 0, 4);
    }

    public static byte[] _sub_securehash_0_4(byte[] b) {
        return Bytes.sub(Hashing.securehash(b), 0, 4);
    }

    public static byte[] _concat_crc32_5(byte[] b) {
        return Bytes.concat(new byte[]{(byte) 0x1a}, Crc32.crc32xmodem(Bytes.sub(b, 5)));
    }

}
