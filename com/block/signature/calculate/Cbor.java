package com.block.signature.calculate;

import com.block.signature.struct.Pair;
import com.block.signature.struct.Triple;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Cbor {

    private static int CBOR_UINT = 0x00;
    private static int CBOR_UINT8_FOLLOWS = 0x18;
    private static int CBOR_UINT16_FOLLOWS = 0x19;
    private static int CBOR_UINT32_FOLLOWS = 0x1a;
    private static int CBOR_UINT64_FOLLOWS = 0x1b;
    private static int CBOR_VAR_FOLLOWS = 0x1f;
    private static int CBOR_NEGINT = 0x20;
    private static int CBOR_BYTES = 0x40;
    private static int CBOR_TEXT = 0x60;
    private static int CBOR_ARRAY = 0x80;
    private static int CBOR_MAP = 0xa0;
    private static int CBOR_TAG = 0xc0;
    private static int CBOR_FALSE = 0xf4;
    private static int CBOR_TRUE = 0xf5;
    private static int CBOR_NULL = 0xf6;
    private static int CBOR_BREAK  = 0xff;

    public static class Tag {
        public BigInteger tag;
        public Object value;
        public Tag(BigInteger tag, Object value) {
            this.tag = tag;
            this.value = value;
        }
    }

    private static Pair<byte[], byte[]> getb(byte[] b, int n) {
        if (b.length < n) throw new IllegalArgumentException("End of input");
        return new Pair<>(Bytes.sub(b, 0, n), Bytes.sub(b, n));
    }

    private static Pair<Integer, byte[]> getf(byte[] b) {
        Pair<byte[], byte[]> t = getb(b, 1);
        byte[] d = t.l;
        b = t.r;
        return new Pair<>(Binint.b2n(d).intValue(), b);
    }

    private static Triple<Integer, BigInteger, byte[]> dec(byte[] b, int f) {
        int t = f & 0xe0, n = f & 0x1f;
        if (n <= 0x17) return new Triple<>(t, BigInteger.valueOf(n), b);
        if (n == CBOR_UINT8_FOLLOWS) {
            Pair<byte[], byte[]> p = getb(b, 1);
            byte[] d = p.l;
            b = p.r;
            return new Triple<>(t, Binint.b2n(d), b);
        }
        if (n == CBOR_UINT16_FOLLOWS) {
            Pair<byte[], byte[]> p = getb(b, 2);
            byte[] d = p.l;
            b = p.r;
            return new Triple<>(t, Binint.b2n(d), b);
        }
        if (n == CBOR_UINT32_FOLLOWS) {
            Pair<byte[], byte[]> p = getb(b, 4);
            byte[] d = p.l;
            b = p.r;
            return new Triple<>(t, Binint.b2n(d), b);
        }
        if (n == CBOR_UINT64_FOLLOWS) {
            Pair<byte[], byte[]> p = getb(b, 8);
            byte[] d = p.l;
            b = p.r;
            return new Triple<>(t, Binint.b2n(d), b);
        }
        if (n != CBOR_VAR_FOLLOWS) throw new IllegalArgumentException("Illegal input");
        return new Triple<>(t, null, b);
    }

    private static Pair<Object, byte[]> loads_rec(byte[] b) {
        return loads_rec(b, null);
    }

    private static Pair<Object, byte[]> loads_rec(byte[] b, Integer f) {
        if (f == null) {
            Pair<Integer, byte[]> t = getf(b);
            f = t.l;
            b = t.r;
        }
        Triple<Integer, BigInteger, byte[]> r = dec(b, f);
        int t = r.l;
        BigInteger n = r.r;
        b = r.t;
        if (f == CBOR_NULL) return new Pair<>(null, b);
        if (f == CBOR_TRUE) return new Pair<>(true, b);
        if (f == CBOR_FALSE) return new Pair<>(false, b);
        if (t == CBOR_UINT) return new Pair<>(n, b);
        if (t == CBOR_NEGINT) return new Pair<>(n.add(BigInteger.ONE).negate(), b);
        if (t == CBOR_BYTES && n != null) {
            Pair<byte[], byte[]> u = getb(b, n.intValue());
            byte[] o = u.l;
            b = u.r;
            return new Pair<>(o, b);
        }
        if (t == CBOR_TEXT && n != null) {
            Pair<byte[], byte[]> u = getb(b, n.intValue());
            byte[] o = u.l;
            b = u.r;
            return new Pair<>(new String(o), b);
        }
        if (t == CBOR_ARRAY && n != null) {
            Object[] o = new Object[n.intValue()];
            for (int i = 0; i < o.length; i++) {
                Pair<Object, byte[]> u = loads_rec(b);
                Object x = u.l;
                b = u.r;
                o[i] = x;
            }
            return new Pair<>(o, b);
        }
        if (t == CBOR_ARRAY) {
            List<Object> o = new ArrayList<>();
            Pair<Integer, byte[]> u = getf(b);
            f = u.l;
            b = u.r;
            while (f != CBOR_BREAK) {
                Pair<Object, byte[]> s = loads_rec(b, f);
                Object x = s.l;
                b = s.r;
                o.add(x);
                u = getf(b);
                f = u.l;
                b = u.r;
            }
            return new Pair<>(o, b);
       }
        if (t == CBOR_MAP && n != null) {
            Map<Object, Object> o = new HashMap<>();
            for (int i = 0; i < n.intValue(); i++) {
                Pair<Object, byte[]> u = loads_rec(b);
                Object k = u.l;
                b = u.r;
                Pair<Object, byte[]> s = loads_rec(b);
                Object v = s.l;
                b = s.r;
                o.put(k, v);
            }
            return new Pair<>(o, b);
        }
        if (t == CBOR_TAG) {
            Pair<Object, byte[]> u = loads_rec(b);
            Object o = u.l;
            b = u.r;
            return new Pair<>(new Tag(n, o), b);
        }
        throw new IllegalStateException("Illegal input");
    }

    public static Object loads(byte[] b) {
        Pair<Object, byte[]> t = loads_rec(b);
        Object o = t.l;
        b = t.r;
        if (b.length != 0) throw new IllegalArgumentException("Illegal input");
        return o;
    }

    private static byte[] enc(int t) {
        return enc(t, BigInteger.ZERO);
    }

    private static byte[] enc(int t, BigInteger v) {
        assert v.compareTo(BigInteger.ZERO) >= 0;
        if (v.compareTo(BigInteger.valueOf(0x17)) <= 0) {
            BigInteger n = BigInteger.valueOf(t|v.intValue());
            return Binint.n2b(n, 1);
        }
        if (v.compareTo(BigInteger.valueOf(0x0ff)) <= 0) {
            BigInteger n = BigInteger.valueOf(t|CBOR_UINT8_FOLLOWS);
            return Bytes.concat(Binint.n2b(n, 1), Binint.n2b(v, 1));
        }
        if (v.compareTo(BigInteger.valueOf(0x0ffff)) <= 0) {
            BigInteger n = BigInteger.valueOf(t|CBOR_UINT16_FOLLOWS);
            return Bytes.concat(Binint.n2b(n, 1), Binint.n2b(v, 2));
        }
        if (v.compareTo(BigInteger.valueOf(0x0ffffffffL)) <= 0) {
            BigInteger n = BigInteger.valueOf(t|CBOR_UINT32_FOLLOWS);
            return Bytes.concat(Binint.n2b(n, 1), Binint.n2b(v, 4));
        }
        if (v.compareTo(new BigInteger("ffffffffffffffff", 16)) <= 0) {
            BigInteger n = BigInteger.valueOf(t|CBOR_UINT64_FOLLOWS);
            return Bytes.concat(Binint.n2b(n, 1), Binint.n2b(v, 8));
        }
        throw new IllegalArgumentException("Exceeds limit");
    }

    public static byte[] dumps(Object o) {
        if (o == null) return enc(CBOR_NULL);
        if (o instanceof Boolean) {
            boolean b = (Boolean)o;
            return enc(b ? CBOR_TRUE : CBOR_FALSE);
        }
        if (o instanceof BigInteger) {
            BigInteger i = (BigInteger)o;
            return i.compareTo(BigInteger.ZERO) >= 0 ? enc(CBOR_UINT, i) : enc(CBOR_NEGINT, i.add(BigInteger.ONE).negate());
        }
        if (o instanceof byte[]) {
            byte[] b = (byte[])o;
            return Bytes.concat(enc(CBOR_BYTES, BigInteger.valueOf(b.length)), b);
        }
        if (o instanceof String) {
            String s = (String)o;
            byte[] b = s.getBytes();
            return Bytes.concat(enc(CBOR_TEXT, BigInteger.valueOf(b.length)), b);
        }
        if (o instanceof Object[]) {
            Object[] a = (Object[])o;
            byte[] b = enc(CBOR_ARRAY, BigInteger.valueOf(a.length));
            for (Object x : a) b = Bytes.concat(b, dumps(x));
            return b;
        }
        if (o instanceof List) {
            List l = (List) o;
            byte[] b = enc(CBOR_ARRAY | CBOR_VAR_FOLLOWS);
            for (Object x : l) b = Bytes.concat(b, dumps(x));
            return Bytes.concat(b, enc(CBOR_BREAK));
        }
        if (o instanceof Map) {
            Map m = (Map)o;
            byte[] b = enc(CBOR_MAP, BigInteger.valueOf(m.size()));
            for (Object key : m.keySet()) b = Bytes.concat(b, dumps(key), dumps(m.get(key)));
            return b;
        }
        if (o instanceof Tag) {
            Tag t = (Tag)o;
            return Bytes.concat(enc(CBOR_TAG, t.tag), dumps(t.value));
        }
        throw new IllegalArgumentException("Unsupported value");
    }

}