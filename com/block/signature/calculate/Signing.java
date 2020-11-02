package com.block.signature.calculate;

import com.block.signature.Coins;
import com.block.signature.struct.Pair;
import com.block.signature.Wallet;

import java.math.BigInteger;

public class Signing {

    private static String arb(BigInteger n) {
        String s = Binint.n2h(n);
        if (s.length() % 2 == 1) s = "0" + s;
        if (Integer.parseInt(s.substring(0, 1), 16) >= 8) s = "00" + s;
        return s;
    }

    private static byte[] signature_encode(Object[] S, String coin, boolean testnet) {
        BigInteger r = (BigInteger) S[0];
        BigInteger s = (BigInteger) S[1];
        Boolean odd = (Boolean) S[2];
        String fmt = Coins.attr("signature.format", coin, testnet);
        if (fmt.equals("der")) {
            if (!Secp256k1.rng(r)) throw new IllegalArgumentException("Out of range");
            if (!Secp256k1.rng(s)) throw new IllegalArgumentException("Out of range");
            if (s.compareTo(Secp256k1.n.shiftRight(1)) > 0) throw new IllegalArgumentException("Out of range");
            byte[] hexr = Binint.h2b(arb(r));
            byte[] hexs = Binint.h2b(arb(s));
            byte[] body = Bytes.concat(new byte[]{0x02, (byte) hexr.length}, hexr, new byte[]{0x02, (byte) hexs.length}, hexs);
            return Bytes.concat(new byte[]{0x30, (byte) body.length}, body);
        }
        if (fmt.equals("rec")) {
            byte[] hexr = Binint.n2b(r, 32);
            byte[] hexs = Binint.n2b(s, 32);
            byte[] hexodd = Binint.n2b(odd ? BigInteger.ONE : BigInteger.ZERO, 1);
            return Bytes.concat(hexr, hexs, hexodd);
        }
        if (fmt.equals("bbe")) {
            byte[] hexr = Binint.n2b(r, 32);
            byte[] hexs = Binint.n2b(s, 32);
            return Bytes.concat(hexr, hexs);
        }
        if (fmt.equals("ble")) {
            byte[] hexr = Bytes.rev(Binint.n2b(r, 32));
            byte[] hexs = Bytes.rev(Binint.n2b(s, 32));
            return Bytes.concat(hexr, hexs);
        }
        if (fmt.equals("blex")) {
            if (odd) s = s.or(BigInteger.ONE.shiftLeft(255));
            byte[] hexr = Bytes.rev(Binint.n2b(r, 32));
            byte[] hexs = Bytes.rev(Binint.n2b(s, 32));
            return Bytes.concat(hexr, hexs);
        }
        throw new IllegalStateException("Unknown format");
    }

    public static Object[] signature_decode(byte[] signature, String coin, boolean testnet) {
        String fmt = Coins.attr("signature.format", coin, testnet);
        if (fmt.equals("der")) {
            if (signature.length < 2) throw new IllegalArgumentException("Invalid signature");
            byte prefix = signature[0];
            int size = (int) signature[1] & 0xff;
            byte[] body = Bytes.sub(signature, 2);
            if (prefix != 0x30) throw new IllegalArgumentException("Invalid signature");
            if (size != body.length) throw new IllegalArgumentException("Invalid signature");
            if (size < 6 || size > 70) throw new IllegalArgumentException("Invalid signature");
            byte prefixr = body[0];
            int sizer = (int)body[1] & 0xff;
            if (prefixr != 0x02) throw new IllegalArgumentException("Invalid signature");
            if (sizer < 1 || sizer > 33) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = Binint.b2n(Bytes.sub(body, 2, 2 + sizer));
            int offset = 2 + sizer;
            byte prefixs = body[offset];
            int sizes = (int) body[offset + 1] & 0xff;
            if (prefixs != 0x02) throw new IllegalArgumentException("Invalid signature");
            if (sizes < 1 || sizes > 33) throw new IllegalArgumentException("Invalid signature");
            BigInteger s = Binint.b2n(Bytes.sub(body, offset + 2, offset + 2 + sizes));
            if (size != 4 + sizer + sizes) throw new IllegalArgumentException("Invalid signature");
            if (!Secp256k1.rng(r)) throw new IllegalArgumentException("Out of range");
            if (!Secp256k1.rng(s)) throw new IllegalArgumentException("Out of range");
            if (s.compareTo(Secp256k1.n.shiftRight(2)) > 0) throw new IllegalArgumentException("Out of range");
            return new Object[]{r, s, null};
        }
        if (fmt.equals("rec")) {
            if (signature.length != 65) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = Binint.b2n(Bytes.sub(signature, 0, 32));
            BigInteger s = Binint.b2n(Bytes.sub(signature, 32, 64));
            boolean odd = Bytes.sub(signature, 64)[0] != 0;
            return new Object[]{r, s, odd};
        }
        if (fmt.equals("bbe")) {
            if (signature.length != 64) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = Binint.b2n(Bytes.sub(signature, 0, 32));
            BigInteger s = Binint.b2n(Bytes.sub(signature, 32));
            return new Object[]{r, s, null};
        }
        if (fmt.equals("ble")) {
            if (signature.length != 64) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = Binint.b2n(Bytes.rev(Bytes.sub(signature, 0, 32)));
            BigInteger s = Binint.b2n(Bytes.rev(Bytes.sub(signature, 32)));
            return new Object[]{r, s, null};
        }
        if (fmt.equals("blex")) {
            if (signature.length != 64) throw new IllegalArgumentException("Invalid signature");
            BigInteger r = Binint.b2n(Bytes.rev(Bytes.sub(signature, 0, 32)));
            BigInteger s = Binint.b2n(Bytes.rev(Bytes.sub(signature, 32)));
            boolean odd = s.shiftRight(255).and(BigInteger.ONE).equals(BigInteger.ONE);
            s = s.and(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE));
            return new Object[]{r, s, odd};
        }
        throw new IllegalStateException("Unknown format");
    }

    public static byte[] signature_create(String privatekey, byte[] data, BigInteger k, String coin, boolean testnet) {
        Pair<BigInteger, Boolean> t = Wallet.privatekey_decode(privatekey, coin, testnet);
        BigInteger e = t.l;
        boolean compressed = t.r;
        String fun = Coins.attr("signature.hashing", "<none>", coin, testnet);
        byte[] prefix = Coins.attr("signature.hashing.prefix", new byte[]{}, coin, testnet);
        byte[] b;
        switch (fun) {
            case "<none>":
                b = Bytes.concat(prefix, data);
                break;
            case "hash256":
                b = Hashing.hash256(Bytes.concat(prefix, data));
                break;
            case "keccak256":
                b = Hashing.keccak256(Bytes.concat(prefix, data));
                break;
            case "sha256":
                b = Hashing.sha256(Bytes.concat(prefix, data));
                break;
            case "sha512h":
                b = Hashing.sha512h(Bytes.concat(prefix, data));
                break;
            case "blake1s":
                b = Hashing.blake1s(Bytes.concat(prefix, data));
                break;
            case "blake2b256":
                b = Hashing.blake2b(data, prefix, 32);
                break;
            default:
                throw new IllegalStateException("Unknown hash function");
        }
        byte[] envelop_prefix = Coins.attr("signature.hashing.envelop.prefix", new byte[]{}, coin, testnet);
        b = Bytes.concat(envelop_prefix, b);
        BigInteger h = Binint.b2n(b);
        int h_len = b.length;
        Object[] S;
        String curve = Coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            if (k == null) k = Hashing.det_k(e, b, Secp256k1.n);
            S = Secp256k1.sgn(e, h, k);
        } else if (curve.equals("nist256p1")) {
            if (k == null) k = Hashing.det_k(e, b, Nist256p1.n);
            S = Nist256p1.sgn(e, h, k);
        }
        else
        if (curve.equals("ed25519")) {
            fun = Coins.attr("ed25519.hashing", "sha512", coin, testnet);
            Hashing.hashfun f;
            switch (fun) {
                case "blake2b":
                    f = Hashing::blake2b;
                    break;
                case "sha512":
                    f = Hashing::sha512;
                    break;
                default:
                    throw new IllegalStateException("Unknown hash function");
            }
            S = Ed25519.sgn(e, h, f, h_len);
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        return signature_encode(S, coin, testnet);
    }

    public static boolean signature_verify(String publickey, byte[] data, byte[] signature, String coin, boolean testnet) {
        Pair<BigInteger[], Boolean> t = Wallet.publickey_decode(publickey, coin, testnet);
        BigInteger[] P = t.l;
        boolean compressed = t.r;
        Object[] S = signature_decode(signature, coin, testnet);
        String fun = Coins.attr("signature.hashing", "<none>", coin, testnet);
        byte[] prefix = Coins.attr("signature.hashing.prefix", new byte[]{}, coin, testnet);
        byte[] b;
        switch (fun) {
            case "<none>":
                b = Bytes.concat(prefix, data);
                break;
            case "hash256":
                b = Hashing.hash256(Bytes.concat(prefix, data));
                break;
            case "keccak256":
                b = Hashing.keccak256(Bytes.concat(prefix, data));
                break;
            case "sha256":
                b = Hashing.sha256(Bytes.concat(prefix, data));
                break;
            case "sha512h":
                b = Hashing.sha512h(Bytes.concat(prefix, data));
                break;
            case "blake1s":
                b = Hashing.blake1s(Bytes.concat(prefix, data));
                break;
            case "blake2b256":
                b = Hashing.blake2b(data, prefix, 32);
                break;
            default:
                throw new IllegalStateException("Unknown hash function");
        }
        byte[] envelop_prefix = Coins.attr("signature.hashing.envelop.prefix", new byte[]{}, coin, testnet);
        b = Bytes.concat(envelop_prefix, b);
        BigInteger h = Binint.b2n(b);
        int h_len = b.length;
        String curve = Coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            return Secp256k1.ver(P, h, S);
        } else if (curve.equals("nist256p1")) {
            return Nist256p1.ver(P, h, S);
        } else
        if (curve.equals("ed25519")) {
            fun = Coins.attr("ed25519.hashing", "sha512", coin, testnet);
            Hashing.hashfun f;
            switch (fun) {
                case "blake2b":
                    f = Hashing::blake2b;
                    break;
                case "sha512":
                    f = Hashing::sha512;
                    break;
                default:
                    throw new IllegalStateException("Unknown hash function");
            }
            return Ed25519.ver(P, h, S, f, h_len);
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
    }

}
