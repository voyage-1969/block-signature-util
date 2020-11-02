package com.block.signature;

import com.block.signature.calculate.*;
import com.block.signature.struct.Pair;
import com.block.signature.struct.Triple;

import java.math.BigInteger;

public class Hdwallet {

    public static String xprivatekey_encode(BigInteger[] k, byte depth, int fingerprint, int child, String coin, boolean testnet) {
        BigInteger e = k[0], c = k[1];
        String curve = Coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            if (!Secp256k1.rng(e)) throw new IllegalArgumentException("Out of range");
        } else if (curve.equals("nist256p1")) {
            if (!Nist256p1.rng(e)) throw new IllegalArgumentException("Out of range");
        } else if (curve.equals("ed25519")) {
        } else {
            throw new IllegalStateException("Unknown curve");
        }
        byte[] b_depth = Binint.n2b(BigInteger.valueOf((int) depth & 0xff), 1);
        byte[] b_fingerprint = Binint.n2b(BigInteger.valueOf((long) fingerprint & 0xffffffffL), 4);
        byte[] b_child = Binint.n2b(BigInteger.valueOf((long) child & 0xffffffffL), 4);
        byte[] chaincode = Binint.n2b(c, 32);
        if (chaincode.length != 32) throw new IllegalArgumentException("Invalid chain code");
        byte[] prefix = new byte[]{0x00};
        byte[] privatekey = Binint.n2b(e, 32);
        byte[] t = Bytes.concat(b_depth, b_fingerprint, b_child, chaincode, prefix, privatekey);
        byte[] version = Coins.attr("xprivatekey.base58.prefix", coin, testnet);
        String fun = Coins.attr("xprivatekey.base58.check", "hash256:4", coin, testnet);
        Hashing.hashfun f;
        if (fun.equals("hash256:4")) f = Base58::_sub_hash256_0_4;
        else if (fun.equals("blake256:4")) f = Base58::_sub_blake256_0_4;
        else {
            throw new IllegalStateException("Unknown hashing function");
        }
        return Base58.check_encode(t, version, new byte[]{}, f);
    }

    public static Object[] xprivatekey_decode(String w, String coin, boolean testnet) {
        byte[] version = Coins.attr("xprivatekey.base58.prefix", coin, testnet);
        String fun = Coins.attr("xprivatekey.base58.check", "hash256:4", coin, testnet);
        int hash_len;
        Hashing.hashfun f;
        if (fun.equals("hash256:4")) {
            hash_len = 4;
            f = Base58::_sub_hash256_0_4;
        } else if (fun.equals("blake256:4")) {
            hash_len = 4;
            f = Base58::_sub_blake256_0_4;
        } else {
            throw new IllegalStateException("Unknown hashing function");
        }
        Triple<byte[], byte[], byte[]> t = Base58.check_decode(w, version.length, 0, hash_len, f);
        byte[] b = t.l, v = t.r;
        if (!Bytes.equ(v, version)) throw new IllegalArgumentException("Invalid prefix");
        if (b.length != 74) throw new IllegalArgumentException("Invalid length");
        byte depth = Binint.b2n(Bytes.sub(b, 0, 1)).byteValue();
        int fingerprint = Binint.b2n(Bytes.sub(b, 1, 5)).intValue();
        int child = Binint.b2n(Bytes.sub(b, 5, 9)).intValue();
        BigInteger c = Binint.b2n(Bytes.sub(b, 9, 41));
        byte[] prefix = Bytes.sub(b, 41, 42);
        BigInteger e = Binint.b2n(Bytes.sub(b, 42));
        if (!Bytes.equ(prefix, new byte[]{0x00})) throw new IllegalArgumentException("Invalid prefix");
        String curve = Coins.attr("ecc.curve", coin, testnet);
        if (curve.equals("secp256k1")) {
            if (!Secp256k1.rng(e)) throw new IllegalArgumentException("Out of range");
        } else if (curve.equals("nist256p1")) {
            if (!Nist256p1.rng(e)) throw new IllegalArgumentException("Out of range");
        } else if (curve.equals("ed25519")) {
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        BigInteger[] k = new BigInteger[]{ e, c };
        return new Object[]{ k, depth, fingerprint, child };
    }

    public static String xprivatekey_master(BigInteger s, String coin, boolean testnet) {
        String curve = Coins.attr("ecc.curve", coin, testnet);
        byte[] salt;
        if (curve.equals("secp256k1")) {
            salt = "Bitcoin seed".getBytes();
        }
        else if (curve.equals("nist256p1")) {
            salt = "Nist256p1 seed".getBytes();
        } else if (curve.equals("ed25519")) {
            salt = "ed25519 seed".getBytes();
        } else {
            throw new IllegalStateException("Unknown curve");
        }
        byte[] I = Hashing.hmac_sha512(salt, Binint.n2b(s, 64));
        BigInteger e = Binint.b2n(Bytes.sub(I, 0, 32));
        BigInteger c = Binint.b2n(Bytes.sub(I, 32));
        BigInteger[] k = new BigInteger[]{e, c};
        return xprivatekey_encode(k, (byte) 0, 0, 0, coin, testnet);
    }

    private static String xpublickey_encode(Object[] K, byte depth, int fingerprint, int child, String coin, boolean testnet) {
        BigInteger[] P = (BigInteger[]) K[0];
        BigInteger c = (BigInteger) K[1];
        byte[] b_depth = Binint.n2b(BigInteger.valueOf((int) depth & 0xff), 1);
        byte[] b_fingerprint = Binint.n2b(BigInteger.valueOf((long) fingerprint & 0xffffffffL), 4);
        byte[] b_child = Binint.n2b(BigInteger.valueOf((long) child & 0xffffffffL), 4);
        byte[] chaincode = Binint.n2b(c, 32);
        if (chaincode.length != 32) throw new IllegalArgumentException("Invalid chain code");
        String curve = Coins.attr("ecc.curve", coin, testnet);
        byte[] prefix;
        byte[] publickey;
        if (curve.equals("secp256k1")) {
            Pair<BigInteger, Boolean> t = Secp256k1.enc(P);
            BigInteger p = t.l;
            boolean odd = t.r;
            prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
            publickey = Binint.n2b(p, 32);
        }
        else
        if (curve.equals("nist256p1")) {
            Pair<BigInteger, Boolean> t = Nist256p1.enc(P);
            BigInteger p = t.l;
            boolean odd = t.r;
            prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
            publickey = Binint.n2b(p, 32);
        } else if (curve.equals("ed25519")) {
            BigInteger p = Ed25519.enc(P);
            prefix = new byte[]{0x00};
            publickey = Bytes.rev(Binint.n2b(p, 32));
        } else {
            throw new IllegalStateException("Unknown curve");
        }
        byte[] t = Bytes.concat(b_depth, b_fingerprint, b_child, chaincode, prefix, publickey);
        byte[] version = Coins.attr("xpublickey.base58.prefix", coin, testnet);
        String fun = Coins.attr("xpublickey.base58.check", "hash256:4", coin, testnet);
        Hashing.hashfun f;
        if (fun.equals("hash256:4")) f = Base58::_sub_hash256_0_4;
        else if (fun.equals("blake256:4")) f = Base58::_sub_blake256_0_4;
        else {
            throw new IllegalStateException("Unknown hashing function");
        }
        return Base58.check_encode(t, version, new byte[]{}, f);
    }

    public static Object[] xpublickey_decode(String w, String coin, boolean testnet) {
        byte[] version = Coins.attr("xpublickey.base58.prefix", coin, testnet);
        String fun = Coins.attr("xprivatekey.base58.check", "hash256:4", coin, testnet);
        int hash_len;
        Hashing.hashfun f;
        if (fun.equals("hash256:4")) {
            hash_len = 4;
            f = Base58::_sub_hash256_0_4;
        } else if (fun.equals("blake256:4")) {
            hash_len = 4;
            f = Base58::_sub_blake256_0_4;
        } else {
            throw new IllegalStateException("Unknown hashing function");
        }
        Triple<byte[], byte[], byte[]> t = Base58.check_decode(w, version.length, 0, hash_len, f);
        byte[] b = t.l, v = t.r;
        if (!Bytes.equ(v, version)) throw new IllegalArgumentException("Invalid prefix");
        if (b.length != 74) throw new IllegalArgumentException("Invalid length");
        byte depth = Binint.b2n(Bytes.sub(b, 0, 1)).byteValue();
        int fingerprint = Binint.b2n(Bytes.sub(b, 1, 5)).intValue();
        int child = Binint.b2n(Bytes.sub(b, 5, 9)).intValue();
        BigInteger c = Binint.b2n(Bytes.sub(b, 9, 41));
        byte[] prefix = Bytes.sub(b, 41, 42);
        String curve = Coins.attr("ecc.curve", coin, testnet);
        BigInteger[] P;
        if (curve.equals("secp256k1")) {
            if (!Bytes.equ(prefix, new byte[]{0x02}) && !Bytes.equ(prefix, new byte[]{0x03}))
                throw new IllegalArgumentException("Invalid prefix");
            boolean odd = !Bytes.equ(prefix, new byte[]{0x02});
            BigInteger p = Binint.b2n(Bytes.sub(b, 42));
            P = Secp256k1.dec(p, odd);
        } else if (curve.equals("nist256p1")) {
            if (!Bytes.equ(prefix, new byte[]{0x02}) && !Bytes.equ(prefix, new byte[]{0x03}))
                throw new IllegalArgumentException("Invalid prefix");
            boolean odd = !Bytes.equ(prefix, new byte[]{0x02});
            BigInteger p = Binint.b2n(Bytes.sub(b, 42));
            P = Nist256p1.dec(p, odd);
        }
        else
        if (curve.equals("ed25519")) {
            if (!Bytes.equ(prefix, new byte[]{0x00})) throw new IllegalArgumentException("Invalid prefix");
            BigInteger p = Binint.b2n(Bytes.rev(Bytes.sub(b, 42)));
            P = Ed25519.dec(p);
        }
        else {
            throw new IllegalStateException("Unknown curve");
        }
        Object[] K = new Object[]{ P, c };
        return new Object[]{ K, depth, fingerprint, child };
    }

    private static Object[] xpublickey_derive(BigInteger[] k, String coin, boolean testnet) {
        BigInteger e = k[0], c = k[1];
        BigInteger[] P = Wallet.publickey_derive(e, coin, testnet);
        return new Object[]{ P, c };
    }

    private static BigInteger[] ckdpriv(BigInteger[] k, int i, String coin, boolean testnet) {
        String curve = Coins.attr("ecc.curve", coin, testnet);
        BigInteger e = k[0], c = k[1];
        boolean hardened = i < 0;
        byte[] chaincode = Binint.n2b(c, 32);
        if (chaincode.length != 32) throw new IllegalArgumentException("Invalid chain code");
        byte[] index = Binint.n2b(BigInteger.valueOf((long) i & 0xffffffffL), 4);
        byte[] I;
        if (hardened) {
            byte[] prefix = new byte[]{0x00};
            byte[] privatekey = Binint.n2b(e, 32);
            I = Hashing.hmac_sha512(chaincode, Bytes.concat(prefix, privatekey, index));
        } else {
            byte[] prefix;
            byte[] publickey;
            if (curve.equals("secp256k1")) {
                BigInteger[] P = Secp256k1.gen(e);
                Pair<BigInteger, Boolean> t = Secp256k1.enc(P);
                BigInteger p = t.l;
                boolean odd = t.r;
                prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
                publickey = Binint.n2b(p, 32);
            }
            else
            if (curve.equals("nist256p1")) {
                BigInteger[] P = Nist256p1.gen(e);
                Pair<BigInteger, Boolean> t = Nist256p1.enc(P);
                BigInteger p = t.l;
                boolean odd = t.r;
                prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
                publickey = Binint.n2b(p, 32);
            } else if (curve.equals("ed25519")) {
                throw new IllegalStateException("Unsupported derivation");
            } else {
                throw new IllegalStateException("Unknown curve");
            }
            I = Hashing.hmac_sha512(chaincode, Bytes.concat(prefix, publickey, index));
        }
        BigInteger ei = Binint.b2n(Bytes.sub(I, 0, 32));
        if (curve.equals("secp256k1")) ei = Secp256k1.aex(e, ei);
        else if (curve.equals("nist256p1")) ei = Nist256p1.aex(e, ei);
        BigInteger ci = Binint.b2n(Bytes.sub(I, 32));
        return new BigInteger[]{ei, ci};
    }

    private static Object[] ckdpub(Object[] K, int i, String coin, boolean testnet) {
        String curve = Coins.attr("ecc.curve", coin, testnet);
        BigInteger[] P = (BigInteger[]) K[0];
        BigInteger c = (BigInteger) K[1];
        boolean hardened = i < 0;
        byte[] chaincode = Binint.n2b(c, 32);
        if (chaincode.length != 32) throw new IllegalArgumentException("Invalid chain code");
        byte[] index = Binint.n2b(BigInteger.valueOf((long) i & 0xffffffffL), 4);
        byte[] I;
        if (hardened) {
            throw new IllegalArgumentException("Invalid index");
        } else {
            byte[] prefix;
            byte[] publickey;
            if (curve.equals("secp256k1")) {
                Pair<BigInteger, Boolean> t = Secp256k1.enc(P);
                BigInteger p = t.l;
                boolean odd = t.r;
                prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
                publickey = Binint.n2b(p, 32);
            }
            else
            if (curve.equals("nist256p1")) {
                Pair<BigInteger, Boolean> t = Nist256p1.enc(P);
                BigInteger p = t.l;
                boolean odd = t.r;
                prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
                publickey = Binint.n2b(p, 32);
            }
            else
            if (curve.equals("ed25519")) {
                throw new IllegalStateException("Unsupported derivation");
            } else {
                throw new IllegalStateException("Unknown curve");
            }
            I = Hashing.hmac_sha512(chaincode, Bytes.concat(prefix, publickey, index));
        }
        BigInteger[] Pi = null;
        if (curve.equals("secp256k1")) Pi = Secp256k1.apt(P, Secp256k1.gen(Binint.b2n(Bytes.sub(I, 0, 32))));
        else if (curve.equals("nist256p1")) Pi = Nist256p1.apt(P, Nist256p1.gen(Binint.b2n(Bytes.sub(I, 0, 32))));
        BigInteger ci = Binint.b2n(Bytes.sub(I, 32));
        return new Object[]{Pi, ci};
    }

    private static int pub_fingerprint(Object[] K, String coin, boolean testnet) {
        BigInteger[] P = (BigInteger[]) K[0];
        BigInteger c = (BigInteger) K[1];
        String curve = Coins.attr("ecc.curve", coin, testnet);
        byte[] prefix;
        byte[] publickey;
        if (curve.equals("secp256k1")) {
            Pair<BigInteger, Boolean> t = Secp256k1.enc(P);
            BigInteger p = t.l;
            boolean odd = t.r;
            prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
            publickey = Binint.n2b(p, 32);
        }
        else
        if (curve.equals("nist256p1")) {
            Pair<BigInteger, Boolean> t = Nist256p1.enc(P);
            BigInteger p = t.l;
            boolean odd = t.r;
            prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
            publickey = Binint.n2b(p, 32);
        } else if (curve.equals("ed25519")) {
            BigInteger p = Ed25519.enc(P);
            prefix = new byte[]{0x00};
            publickey = Bytes.rev(Binint.n2b(p, 32));
        } else {
            throw new IllegalStateException("Unknown curve");
        }
        byte[] b = Bytes.concat(prefix, publickey);
        byte[] h = Bytes.sub(Hashing.hash160(b), 0, 4);
        return Binint.b2n(h).intValue();
    }

    private static Object[] ckdpriv_path(BigInteger[] k, byte depth, int fingerprint, int child, String path, String coin, boolean testnet) {
        String[] indexes = path.split("/");
        for (String index: indexes) {
            child =  index.substring(index.length()-1, index.length()).equals("'")
                    ? 0x80000000 + Integer.valueOf(index.substring(0, index.length()-1))
                    : Integer.valueOf(index);
            fingerprint = pub_fingerprint(xpublickey_derive(k, coin, testnet), coin, testnet);
            depth++;
            k = ckdpriv(k, child, coin, testnet);
        }
        return new Object[]{ k, depth, fingerprint, child };
    }

    private static Object[] ckdpub_path(Object[] K, byte depth, int fingerprint, int child, String path, String coin, boolean testnet) {
        String[] indexes = path.split("/");
        for (String index: indexes) {
            child =  index.substring(index.length()-1, index.length()).equals("'")
                    ? 0x80000000 + Integer.valueOf(index.substring(0, index.length()-1))
                    : Integer.valueOf(index);
            fingerprint = pub_fingerprint(K, coin, testnet);
            depth++;
            K = ckdpub(K, child, coin, testnet);
        }
        return new Object[]{ K, depth, fingerprint, child };
    }

    public static String xprivatekey_from_xprivatekey(String w, String path, String coin, boolean testnet) {
        if (!path.matches("^[mk](/\\d+'?)*$")) throw new IllegalArgumentException("Invalid path");
        Object[] t = xprivatekey_decode(w, coin, testnet);
        BigInteger[] k = (BigInteger[]) t[0];
        byte depth = (byte) t[1];
        int fingerprint = (int) t[2];
        int child = (int) t[3];
        if (depth == 0 && (fingerprint != 0 || child != 0)) throw new IllegalArgumentException("Invalid master");
        if (path.substring(0, 1).equals("m") && depth != 0) throw new IllegalArgumentException("Master expected");
        t = ckdpriv_path(k, depth, fingerprint, child, path.substring(2), coin, testnet);
        k = (BigInteger[]) t[0];
        depth = (byte) t[1];
        fingerprint = (int) t[2];
        child = (int) t[3];
        return xprivatekey_encode(k, depth, fingerprint, child, coin, testnet);
    }

    public static String xpublickey_from_xpublickey(String w, String path, String coin, boolean testnet) {
        if (!path.matches("^[MK](/\\d+'?)*$")) throw new IllegalArgumentException("Invalid path");
        Object[] t = xpublickey_decode(w, coin, testnet);
        Object[] K = (Object[]) t[0];
        byte depth = (byte) t[1];
        int fingerprint = (int) t[2];
        int child = (int) t[3];
        if (depth == 0 && (fingerprint != 0 || child != 0)) throw new IllegalArgumentException("Invalid master");
        if (path.substring(0, 1).equals("M") && depth != 0) throw new IllegalArgumentException("Master expected");
        t = ckdpub_path(K, depth, fingerprint, child, path.substring(2), coin, testnet);
        K = (Object[]) t[0];
        depth = (byte) t[1];
        fingerprint = (int) t[2];
        child = (int) t[3];
        return xpublickey_encode(K, depth, fingerprint, child, coin, testnet);
    }

    public static String xpublickey_from_xprivatekey(String w, String coin, boolean testnet) {
        Object[] t = xprivatekey_decode(w, coin, testnet);
        BigInteger[] k = (BigInteger[]) t[0];
        byte depth = (byte) t[1];
        int fingerprint = (int) t[2];
        int child = (int) t[3];
        Object[] K = xpublickey_derive(k, coin, testnet);
        return xpublickey_encode(K, depth, fingerprint, child, coin, testnet);
    }

    public static String privatekey_from_xprivatekey(String w, boolean compressed, String coin, boolean testnet) {
        Object[] t = xprivatekey_decode(w, coin, testnet);
        BigInteger[] k = (BigInteger[]) t[0];
        byte depth = (byte) t[1];
        int fingerprint = (int) t[2];
        int child = (int) t[3];
        BigInteger e = k[0], c = k[1];
        return Wallet.privatekey_encode(e, compressed, coin, testnet);
    }

    public static String publickey_from_xpublickey(String w, boolean compressed, String coin, boolean testnet) {
        Object[] t = xpublickey_decode(w, coin, testnet);
        Object[] K = (Object[]) t[0];
        byte depth = (byte) t[1];
        int fingerprint = (int) t[2];
        int child = (int) t[3];
        BigInteger[] P = (BigInteger[]) K[0];
        BigInteger c = (BigInteger) K[1];
        return Wallet.publickey_encode(P, compressed, coin, testnet);
    }

    public static String path(String coin, boolean testnet) {
        return path(-1, false, 0, 44, coin, testnet);
    }

    public static String path(int account, String coin, boolean testnet) {
        return path(-1, false, account, 44, coin, testnet);
    }

    public static String path(int address_index, boolean change, int account, String coin, boolean testnet) {
        return path(address_index, change, account, 44, coin, testnet);
    }

    public static String path(int address_index, boolean change, int account, int purpose, String coin, boolean testnet) {
        int coin_type = testnet ? 1 : Coins.attr("hdwallet.coin_type", coin, false);
        String path = "m";
        if (purpose < 0) return path;
        path += "/" + purpose + "'";
        if (coin_type < 0) return path;
        path += "/" + coin_type + "'";
        if (account < 0) return path;
        path += "/" + account + "'";
        if (address_index < 0) return path;
        path += "/" + (change ? 1 : 0);
        path += "/" + address_index;
        return path;
    }

}
