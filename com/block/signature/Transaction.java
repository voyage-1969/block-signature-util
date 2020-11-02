package com.block.signature;

import com.block.signature.calculate.*;
import com.block.signature.struct.Dict;
import com.block.signature.struct.Pair;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Transaction {

    public static final int SIGHASH_ALL = 0x01;
    public static final int SIGHASH_NONE = 0x02;
    public static final int SIGHASH_SINGLE = 0x03;
    public static final int SIGHASH_FORKID = 0x40;          // bitcoin fork
    public static final int SIGHASH_ANYONECANPAY = 0x80;

    private static void r(byte[] b) {
        for (int i = 0, j = b.length - 1; i < j; i++, j--) {
            byte t = b[i];
            b[i] = b[j];
            b[j] = t;
        }
    }

    private static byte[] int8(BigInteger n) {
        return int8(n, true);
    }

    private static byte[] int8(BigInteger n, boolean r) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(8)) >= 0) throw new IllegalArgumentException("Invalid constant");
        return Binint.n2b(n, 1);
    }

    private static Pair<BigInteger, byte[]> parse_int8(byte[] b) {
        return parse_int8(b, true);
    }

    private static Pair<BigInteger, byte[]> parse_int8(byte[] b, boolean r) {
        if (b.length < 1) throw new IllegalArgumentException("End of input");
        byte[] t1 = Bytes.sub(b, 0, 1);
        byte[] t2 = Bytes.sub(b, 1);
        return new Pair<>(Binint.b2n(t1), t2);
    }

    private static byte[] int16(BigInteger n) {
        return int16(n, true);
    }

    private static byte[] int16(BigInteger n, boolean r) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(16)) >= 0) throw new IllegalArgumentException("Invalid constant");
        byte[] b = Binint.n2b(n, 2);
        if (r) r(b);
        return b;
    }

    private static Pair<BigInteger, byte[]> parse_int16(byte[] b) {
        return parse_int16(b, true);
    }

    private static Pair<BigInteger, byte[]> parse_int16(byte[] b, boolean r) {
        if (b.length < 2) throw new IllegalArgumentException("End of input");
        byte[] t1 = Bytes.sub(b, 0, 2);
        byte[] t2 = Bytes.sub(b, 2);
        if (r) r(t1);
        return new Pair<>(Binint.b2n(t1), t2);
    }

    private static byte[] int32(BigInteger n) {
        return int32(n, true);
    }

    private static byte[] int32(BigInteger n, boolean r) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(32)) >= 0) throw new IllegalArgumentException("Invalid constant");
        byte[] b = Binint.n2b(n, 4);
        if (r) r(b);
        return b;
    }

    private static Pair<BigInteger, byte[]> parse_int32(byte[] b) {
        return parse_int32(b, true);
    }

    private static Pair<BigInteger, byte[]> parse_int32(byte[] b, boolean r) {
        if (b.length < 4) throw new IllegalArgumentException("End of input");
        byte[] t1 = Bytes.sub(b, 0, 4);
        byte[] t2 = Bytes.sub(b, 4);
        if (r) r(t1);
        return new Pair<>(Binint.b2n(t1), t2);
    }

    private static byte[] int64(BigInteger n) {
        return int64(n, true);
    }

    private static byte[] int64(BigInteger n, boolean r) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(64)) >= 0) throw new IllegalArgumentException("Invalid constant");
        byte[] b = Binint.n2b(n, 8);
        if (r) r(b);
        return b;
    }

    private static Pair<BigInteger, byte[]> parse_int64(byte[] b) {
        return parse_int64(b, true);
    }

    private static Pair<BigInteger, byte[]> parse_int64(byte[] b, boolean r) {
        if (b.length < 8) throw new IllegalArgumentException("End of input");
        byte[] t1 = Bytes.sub(b, 0, 8);
        byte[] t2 = Bytes.sub(b, 8);
        if (r) r(t1);
        return new Pair<>(Binint.b2n(t1), t2);
    }

    private static byte[] varint(BigInteger n) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(64)) >= 0) throw new IllegalArgumentException("Invalid constant");
        byte[] t1;
        byte[] t2;
        if (n.compareTo(BigInteger.ONE.shiftLeft(32)) >= 0) {
            t1 = int8(BigInteger.valueOf((1<<8)-1));
            t2 = int64(n);
        } else if (n.compareTo(BigInteger.ONE.shiftLeft(16)) >= 0) {
            t1 = int8(BigInteger.valueOf((1<<8)-2));
            t2 = int32(n);
        } else if (n.compareTo(BigInteger.ONE.shiftLeft(8).subtract(BigInteger.valueOf(3))) >= 0) {
            t1 = int8(BigInteger.valueOf((1 << 8) - 3));
            t2 = int16(n);
        } else {
            t1 = new byte[]{};
            t2 = int8(n);
        }
        return Bytes.concat(t1, t2);
    }

    private static Pair<BigInteger, byte[]> parse_varint(byte[] b) {
        Pair<BigInteger, byte[]> r = parse_int8(b);
        BigInteger n = r.l;
        b = r.r;
        if (n.compareTo(BigInteger.valueOf((1 << 8) - 1)) == 0) return parse_int64(b);
        if (n.compareTo(BigInteger.valueOf((1 << 8) - 2)) == 0) return parse_int32(b);
        if (n.compareTo(BigInteger.valueOf((1 << 8) - 3)) == 0) return parse_int16(b);
        return r;
    }

    private static byte[] nlzint(BigInteger n) {
        if (n.compareTo(BigInteger.ZERO) < 0 || n.compareTo(BigInteger.ONE.shiftLeft(256)) >= 0)
            throw new IllegalArgumentException("Invalid constant");
        if (n.equals(BigInteger.ZERO)) return new byte[]{ };
        String s = Binint.n2h(n);
        if (s.length() % 2 == 1) s = "0" + s;
        return Binint.h2b(s);
    }

    private static Pair<BigInteger, byte[]> parse_nlzint(byte[] b) {
        return parse_nlzint(b, -1);
    }

    private static Pair<BigInteger, byte[]> parse_nlzint(byte[] b, int l) {
        if (l == -1) l = b.length;
        if (b.length < l) throw new IllegalArgumentException("End of input");
        byte[] b1 = Bytes.sub(b, 0, l);
        byte[] b2 = Bytes.sub(b, l);
        if (b1.length == 0) return new Pair<>(BigInteger.ZERO, b2);
        if (b1[0] == 0x00) throw new IllegalArgumentException("Invalid encoding");
        BigInteger n = Binint.b2n(b1);
        if (n.compareTo(BigInteger.ONE.shiftLeft(256)) >= 0) throw new IllegalArgumentException("Invalid encoding");
        return new Pair<>(n, b2);
    }

    private static byte[] rlp_varlen(int base, int n) {
        if (n > 55) {
            byte[] b = nlzint(BigInteger.valueOf(n));
            byte[] r = int8(BigInteger.valueOf(base + 55 + b.length));
            return Bytes.concat(r, b);
        }
        return int8(BigInteger.valueOf(base + n));
    }

    private static byte[] rlp(Object v) {
        if (v instanceof byte[]) {
            byte[] b = (byte[]) v;
            if (b.length == 1) {
                Pair<BigInteger, byte[]> r = parse_int8(b);
                BigInteger n = r.l;
                if (n.intValue() < 0x80) return b;
            }
            byte[] r = rlp_varlen(0x80, b.length);
            return Bytes.concat(r, b);
        }
        if (v instanceof Object[]) {
            Object[] l = (Object[]) v;
            byte[][] a = new byte[l.length][];
            int length = 0;
            for (int i = 0; i < l.length; i++) {
                a[i] = rlp(l[i]);
                length += a[i].length;
            }
            byte[] b = new byte[length];
            int offset = 0;
            for (int i = 0; i < l.length; i++) {
                System.arraycopy(a[i], 0, b, offset, a[i].length);
                offset += a[i].length;
            }
            byte[] r = rlp_varlen(0xc0, b.length);
            return Bytes.concat(r, b);
        }
        throw new IllegalArgumentException("Unsupported datatype");
    }

    private static Object[] rlp_parse_varlen(byte[] b) {
        Pair<BigInteger, byte[]> r = parse_int8(b);
        int n = r.l.intValue();
        b = r.r;
        if (n >= 0xc0 + 56) {
            r = parse_nlzint(b, n - (0xc0 + 56) + 1);
            BigInteger l = r.l;
            b = r.r;
            if (l.compareTo(BigInteger.valueOf(56)) < 0) throw new IllegalArgumentException("Invalid encoding");
            return new Object[]{ "list", l, b };
        }
        if (n >= 0xc0) {
            BigInteger l = BigInteger.valueOf(n - 0xc0);
            return new Object[]{ "list", l, b };
        }
        if (n >= 0x80 + 56) {
            r = parse_nlzint(b, n - (0x80 + 56) + 1);
            BigInteger l = r.l;
            b = r.r;
            if (l.compareTo(BigInteger.valueOf(56)) < 0) throw new IllegalArgumentException("Invalid encoding");
            return new Object[]{ "str", l, b };
        }
        if (n >= 0x80) {
            BigInteger l = BigInteger.valueOf(n - 0x80);
            if (l.equals(BigInteger.ONE)) {
                r = parse_int8(b);
                n = r.l.intValue();
                if (n < 0x80) throw new IllegalArgumentException("Invalid encoding");
            }
            return new Object[]{ "str", l, b };
        }
        byte[] v = int8(BigInteger.valueOf(n));
        return new Object[]{"str", BigInteger.ONE, Bytes.concat(v, b)};
    }

    private static Pair<Object, byte[]> parse_rlp(byte[] b) {
        Object[] r = rlp_parse_varlen(b);
        String t = (String) r[0];
        int l = ((BigInteger) r[1]).intValue();
        b = (byte[]) r[2];
        if (l > b.length) throw new IllegalArgumentException("End of input");
        byte[] b1 = Bytes.sub(b, 0, l);
        byte[] b2 = Bytes.sub(b, l);
        if (t.equals("str")) return new Pair<>(b1, b2);
        if (t.equals("list")) {
            List<Object> list = new ArrayList<>();
            while (b1.length > 0) {
                Pair<Object, byte[]> s = parse_rlp(b1);
                Object v = s.l;
                b1 = s.r;
                list.add(v);
            }
            Object[] vs = list.toArray();
            return new Pair<>(vs, b2);
        }
        throw new IllegalArgumentException("Unknown type");
    }

    private static final String[][] RIPPLE_FIELDS = {
        {"1", "2", "TransactionType"},
        {"2", "2", "Flags"},
        {"2", "4", "Sequence"},
        {"2", "e", "DestinationTag"},
        {"2", "01b", "LastLedgerSequence"},
        {"5", "011", "InvoiceID"},
        {"6", "1", "Amount"},
        {"6", "8", "Fee"},
        {"7", "3", "SigningPubKey"},
        {"7", "4", "TxnSignature"},
        {"8", "1", "Account"},
        {"8", "3", "Destination"},
    };

    private static byte[] serial_varlen(int n) {
        if (n <= 0xc0) return Binint.n2b(BigInteger.valueOf(n), 1);
        if (n <= 0x30c0) return Binint.n2b(BigInteger.valueOf((0xc1 << 8) + (n - 0xc1)), 2);
        if (n <= 0x0e30c0) return Binint.n2b(BigInteger.valueOf((0xf1 << 16) + (n - 0x30c1)), 3);
        throw new IllegalArgumentException("Capacity overflow");
    }

    private static byte[] serial(Dict fields) {
        List<byte[]> items = new ArrayList<>();
        for (String[] ripple_field : RIPPLE_FIELDS) {
            String mode = ripple_field[0];
            String code = ripple_field[1];
            String name = ripple_field[2];
            if (!fields.has(name)) continue;
            byte[] prefix = Binint.h2b(mode + code);
            byte[] item;
            if (mode.equals("1")) {
                BigInteger value = fields.get(name);
                item = int16(value, false);
            } else if (mode.equals("2") || mode.equals("5")) {
                BigInteger value = fields.get(name);
                item = int32(value, false);
            } else if (mode.equals("6")) {
                BigInteger value = fields.get(name);
                item = int64(value, false);
            } else if (mode.equals("7") || mode.equals("8")) {
                byte[] data = fields.get(name);
                byte[] b = serial_varlen(data.length);
                item = Bytes.concat(b, data);
            } else {
                throw new IllegalArgumentException("Unknown mode");
            }
            items.add(Bytes.concat(prefix, item));
        }
        int length = 0;
        for (byte[] item : items) length += item.length;
        byte[] b = new byte[length];
        int offset = 0;
        for (byte[] item : items) {
            System.arraycopy(item, 0, b, offset, item.length);
            offset += item.length;
        }
        return b;
    }

    private static Pair<Integer, byte[]> serial_parse_varlen(byte[] b) {
        Pair<BigInteger, byte[]> r = parse_int8(b, false);
        int n = r.l.intValue();
        b = r.r;
        if (n <= 0xc0) {
            return new Pair<>(n, b);
        }
        if (n <= 0xf0) {
            Pair<BigInteger, byte[]> t = parse_int8(b, false);
            int k = t.l.intValue();
            b = t.r;
            n = (n << 8) + k;
            return new Pair<>((n + 0xc1) - (0xc1 << 8), b);
        }
        if (n <= 0xfe) {
            Pair<BigInteger, byte[]> t = parse_int16(b, false);
            int k = t.l.intValue();
            b = t.r;
            n = (n << 16) + k;
            return new Pair<>((n + 0x30c1) - (0xf1 << 16), b);
        }
        throw new IllegalArgumentException("Invalid encoding");
    }

    private static Object[] serial_parse_prefix(byte[] b) {
        for (String[] ripple_field : RIPPLE_FIELDS) {
            String mode = ripple_field[0];
            String code = ripple_field[1];
            String name = ripple_field[2];
            byte[] prefix = Binint.h2b(mode + code);
            int l = prefix.length;
            if (l > b.length) continue;
            byte[] b1 = Bytes.sub(b, 0, l);
            byte[] b2 = Bytes.sub(b, l);
            if (Arrays.equals(b1, prefix)) {
                return new Object[]{mode, code, name, b2};
            }
        }
        throw new IllegalArgumentException("Unsupported prefix");
    }

    private static Dict parse_serial(byte[] b) {
        Dict fields = new Dict();
        while (b.length > 0) {
            Object[] r = serial_parse_prefix(b);
            String mode = (String) r[0];
            String code = (String) r[1];
            String name = (String) r[2];
            b = (byte[]) r[3];
            Object value;
            if (mode.equals("1")) {
                Pair<BigInteger, byte[]> t = parse_int16(b, false);
                value = t.l;
                b = t.r;
            } else if (mode.equals("2") || mode.equals("5")) {
                Pair<BigInteger, byte[]> t = parse_int32(b, false);
                value = t.l;
                b = t.r;
            } else if (mode.equals("6")) {
                Pair<BigInteger, byte[]> t = parse_int64(b, false);
                value = t.l;
                b = t.r;
            } else if (mode.equals("7") || mode.equals("8")) {
                Pair<Integer, byte[]> t = serial_parse_varlen(b);
                int l = t.l;
                b = t.r;
                if (b.length < l) throw new IllegalArgumentException("End of input");
                byte[] b1 = Bytes.sub(b, 0, l);
                byte[] b2 = Bytes.sub(b, l);
                value = b1;
                b = b2;
            } else {
                throw new IllegalArgumentException("Unknown mode");
            }
            fields.put(name, value);
        }
        return fields;
    }

    private static byte[] inout_input_encode(Dict fields, BigInteger default_sequence) {
        String txnid = fields.get("txnid");
        BigInteger index = fields.get("index", BigInteger.ZERO);
        byte[] inscript = fields.get("script", new byte[]{});
        BigInteger sequence = fields.get("sequence", default_sequence);
        byte[] b1 = Binint.h2b(txnid);
        r(b1);
        byte[] b2 = int32(index);
        byte[] b3 = varint(BigInteger.valueOf(inscript.length));
        byte[] b4 = inscript;
        byte[] b5 = int32(sequence);
        return Bytes.concat(b1, b2, b3, b4, b5);
    }

    private static byte[] inout_output_encode(Dict fields, String coin, boolean testnet) {
        BigInteger amount = fields.get("amount", BigInteger.ZERO);
        byte[] outscript = fields.get("script", null);
        if (outscript == null) {
            String address = fields.get("address", null);
            String message = fields.get("message", null);
            outscript = Script.scriptpubkey(address, message, coin, testnet);
        }
        byte[] b1 = int64(amount);
        byte[] b2 = varint(BigInteger.valueOf(outscript.length));
        byte[] b3 = outscript;
        return Bytes.concat(b1, b2, b3);
    }

    private static byte[] dcrinout_input_encode(Dict fields, BigInteger default_sequence) {
        String txnid = fields.get("txnid");
        BigInteger index = fields.get("index", BigInteger.ZERO);
        BigInteger tree = fields.get("tree", BigInteger.ZERO);
        BigInteger sequence = fields.get("sequence", default_sequence);
        byte[] b1 = Bytes.rev(Binint.h2b(txnid));
        byte[] b2 = int32(index);
        byte[] b3 = int8(tree);
        byte[] b4 = int32(sequence);
        return Bytes.concat(b1, b2, b3, b4);
    }

    private static byte[] dcrinout_output_encode(Dict fields, String coin, boolean testnet) {
        BigInteger amount = fields.get("amount", BigInteger.ZERO);
        BigInteger version = fields.get("version", BigInteger.ZERO);
        byte[] outscript = fields.get("script", null);
        if (outscript == null) {
            String address = fields.get("address", null);
            String message = fields.get("message", null);
            outscript = Script.scriptpubkey(address, message, coin, testnet);
        }
        byte[] b1 = int64(amount);
        byte[] b2 = int16(version);
        byte[] b3 = varint(BigInteger.valueOf(outscript.length));
        byte[] b4 = outscript;
        return Bytes.concat(b1, b2, b3, b4);
    }

    private static byte[] dcrinout_witness_encode(Dict fields) {
        BigInteger amount = fields.get("amount", BigInteger.ZERO);
        BigInteger blockheight = fields.get("blockheight", BigInteger.ZERO);
        BigInteger blockindex = fields.get("blockindex", BigInteger.valueOf(0x0ffffffffL));
        byte[] inscript = fields.get("script", new byte[]{});
        byte[] b1 = int64(amount);
        byte[] b2 = int32(blockheight);
        byte[] b3 = int32(blockindex);
        byte[] b4 = varint(BigInteger.valueOf(inscript.length));
        byte[] b5 = inscript;
        return Bytes.concat(b1, b2, b3, b4, b5);
    }

    private static byte[] neoinout_input_encode(Dict fields) {
        String txnid = fields.get("txnid");
        BigInteger index = fields.get("index", BigInteger.ZERO);
        byte[] b1 = Bytes.rev(Binint.h2b(txnid));
        byte[] b2 = int16(index);
        return Bytes.concat(b1, b2);
    }

    private static byte[] neoinout_output_encode(Dict fields, String coin, boolean testnet) {
        String asset = fields.get("asset");
        BigInteger amount = fields.get("amount", BigInteger.ZERO);
        String address = fields.get("address");
        Pair<BigInteger, String> t = Wallet.address_decode(address, coin, testnet);
        BigInteger h = t.l;
        String kind = t.r;
        byte[] b1 = Bytes.rev(Binint.h2b(asset));
        byte[] b2 = int64(amount);
        byte[] b3 = Binint.n2b(h, 20);
        return Bytes.concat(b1, b2, b3);
    }

    private static byte[] neoinout_script_encode(Dict fields) {
        byte[] invocation_script = fields.get("invocation");
        byte[] verification_script = fields.get("verification");
        byte[] b1 = varint(BigInteger.valueOf(invocation_script.length));
        byte[] b2 = invocation_script;
        byte[] b3 = varint(BigInteger.valueOf(verification_script.length));
        byte[] b4 = verification_script;
        return Bytes.concat(b1, b2, b3, b4);
    }

    public static byte[] transaction_encode(Dict fields, String coin, boolean testnet) {
        String fmt = Coins.attr("transaction.format", coin, testnet);
        if (fmt.equals("inout")) {
            int default_version = Coins.attr("transaction.version", 1, coin, testnet);
            BigInteger version = fields.get("version", BigInteger.valueOf(default_version & 0x0ffffffffL));
            Dict[] inputs = fields.get("inputs", new Dict[]{});
            Dict[] outputs = fields.get("outputs", new Dict[]{});
            BigInteger locktime = fields.get("locktime", BigInteger.ZERO);
            BigInteger default_sequence = locktime.compareTo(BigInteger.ZERO) > 0 ? BigInteger.ZERO : BigInteger.valueOf(0x0ffffffffL);
            if (version.equals(BigInteger.valueOf(0x080000004L))) { // zcash sapling
                int default_groupid = Coins.attr("transaction.groupid", coin, testnet);
                BigInteger groupid = fields.get("groupid", BigInteger.valueOf(default_groupid & 0x0ffffffffL));
                BigInteger expiryheight = fields.get("expiryheight", BigInteger.ZERO);
                byte[] b1 = int32(version);
                byte[] b2 = int32(groupid);
                byte[] b3 = varint(BigInteger.valueOf(inputs.length));
                int inputs_length = 0;
                byte[][] b_inputs = new byte[inputs.length][];
                for (int i = 0; i < inputs.length; i++) {
                    byte[] b_input = inout_input_encode(inputs[i], default_sequence);
                    b_inputs[i] = b_input;
                    inputs_length += b_input.length;
                }
                byte[] b4 = new byte[inputs_length];
                int inputs_offset = 0;
                for (byte[] b_input : b_inputs) {
                    System.arraycopy(b_input, 0, b4, inputs_offset, b_input.length);
                    inputs_offset += b_input.length;
                }
                byte[] b5 = varint(BigInteger.valueOf(outputs.length));
                int outputs_length = 0;
                byte[][] b_outputs = new byte[outputs.length][];
                for (int i = 0; i < outputs.length; i++) {
                    byte[] b_output = inout_output_encode(outputs[i], coin, testnet);
                    b_outputs[i] = b_output;
                    outputs_length += b_output.length;
                }
                byte[] b6 = new byte[outputs_length];
                int outputs_offset = 0;
                for (byte[] b_output : b_outputs) {
                    System.arraycopy(b_output, 0, b6, outputs_offset, b_output.length);
                    outputs_offset += b_output.length;
                }
                byte[] b7 = int32(locktime);
                byte[] b8 = int32(expiryheight);
                byte[] b9 = int64(BigInteger.ZERO);
                byte[] b10 = varint(BigInteger.ZERO);
                byte[] b11 = varint(BigInteger.ZERO);
                byte[] b12 = varint(BigInteger.ZERO);
                return Bytes.concat(Bytes.concat(b1, b2, b3, b4, b5, b6), Bytes.concat(b7, b8, b9, b10, b11, b12));
            }
            byte[] b1 = int32(version);
            byte[] b2 = varint(BigInteger.valueOf(inputs.length));
            int inputs_length = 0;
            byte[][] b_inputs = new byte[inputs.length][];
            for (int i = 0; i < inputs.length; i++) {
                byte[] b_input = inout_input_encode(inputs[i], default_sequence);
                b_inputs[i] = b_input;
                inputs_length += b_input.length;
            }
            byte[] b3 = new byte[inputs_length];
            int inputs_offset = 0;
            for (byte[] b_input : b_inputs) {
                System.arraycopy(b_input, 0, b3, inputs_offset, b_input.length);
                inputs_offset += b_input.length;
            }
            byte[] b4 = varint(BigInteger.valueOf(outputs.length));
            int outputs_length = 0;
            byte[][] b_outputs = new byte[outputs.length][];
            for (int i = 0; i < outputs.length; i++) {
                byte[] b_output = inout_output_encode(outputs[i], coin, testnet);
                b_outputs[i] = b_output;
                outputs_length += b_output.length;
            }
            byte[] b5 = new byte[outputs_length];
            int outputs_offset = 0;
            for (byte[] b_output : b_outputs) {
                System.arraycopy(b_output, 0, b5, outputs_offset, b_output.length);
                outputs_offset += b_output.length;
            }
            byte[] b6 = int32(locktime);
            return Bytes.concat(b1, b2, b3, b4, b5, b6);
        }
        if (fmt.equals("dcrinout")) {
            BigInteger version = fields.get("version", BigInteger.ONE);
            Dict[] inputs = fields.get("inputs", new Dict[]{});
            Dict[] outputs = fields.get("outputs", new Dict[]{});
            BigInteger locktime = fields.get("locktime", BigInteger.ZERO);
            BigInteger expiryheight = fields.get("expiryheight", BigInteger.ZERO);
            Dict[] witnesses = fields.get("witnesses", null);
            BigInteger default_sequence = locktime.compareTo(BigInteger.ZERO) > 0 ? BigInteger.ZERO : BigInteger.valueOf(0x0ffffffffL);
            byte[] b1 = int32(version);
            byte[] b2 = varint(BigInteger.valueOf(inputs.length));
            int inputs_length = 0;
            byte[][] b_inputs = new byte[inputs.length][];
            for (int i = 0; i < inputs.length; i++) {
                byte[] b_input = dcrinout_input_encode(inputs[i], default_sequence);
                b_inputs[i] = b_input;
                inputs_length += b_input.length;
            }
            byte[] b3 = new byte[inputs_length];
            int inputs_offset = 0;
            for (byte[] b_input : b_inputs) {
                System.arraycopy(b_input, 0, b3, inputs_offset, b_input.length);
                inputs_offset += b_input.length;
            }
            byte[] b4 = varint(BigInteger.valueOf(outputs.length));
            int outputs_length = 0;
            byte[][] b_outputs = new byte[outputs.length][];
            for (int i = 0; i < outputs.length; i++) {
                byte[] b_output = dcrinout_output_encode(outputs[i], coin, testnet);
                b_outputs[i] = b_output;
                outputs_length += b_output.length;
            }
            byte[] b5 = new byte[outputs_length];
            int outputs_offset = 0;
            for (byte[] b_output : b_outputs) {
                System.arraycopy(b_output, 0, b5, outputs_offset, b_output.length);
                outputs_offset += b_output.length;
            }
            byte[] b6 = int32(locktime);
            byte[] b7 = int32(expiryheight);
            byte[] b8 = new byte[]{};
            byte[] b9 = new byte[]{};
            if (witnesses != null) {
                b8 = varint(BigInteger.valueOf(witnesses.length));
                int witnesses_length = 0;
                byte[][] b_witnesses = new byte[witnesses.length][];
                for (int i = 0; i < witnesses.length; i++) {
                    byte[] b_witness = dcrinout_witness_encode(witnesses[i]);
                    b_witnesses[i] = b_witness;
                    witnesses_length += b_witness.length;
                }
                b9 = new byte[witnesses_length];
                int witnesses_offset = 0;
                for (byte[] b_witness : b_witnesses) {
                    System.arraycopy(b_witness, 0, b9, witnesses_offset, b_witness.length);
                    witnesses_offset += b_witness.length;
                }
            }
            return Bytes.concat(Bytes.concat(b1, b2, b3, b4, b5, b6), b7, b8, b9);
        }
        if (fmt.equals("neoinout")) {
            BigInteger txtype = fields.get("type", BigInteger.valueOf(0x80));
            BigInteger version = fields.get("version", BigInteger.ZERO);
            Dict[] inputs = fields.get("inputs", new Dict[]{});
            Dict[] outputs = fields.get("outputs", new Dict[]{});
            Dict[] scripts = fields.get("scripts", null);
            byte[] b1 = int8(txtype);
            byte[] b2 = int8(version);
            byte[] b3 = varint(BigInteger.ZERO);
            byte[] b4 = varint(BigInteger.valueOf(inputs.length));
            int inputs_length = 0;
            byte[][] b_inputs = new byte[inputs.length][];
            for (int i = 0; i < inputs.length; i++) {
                byte[] b_input = neoinout_input_encode(inputs[i]);
                b_inputs[i] = b_input;
                inputs_length += b_input.length;
            }
            byte[] b5 = new byte[inputs_length];
            int inputs_offset = 0;
            for (byte[] b_input : b_inputs) {
                System.arraycopy(b_input, 0, b5, inputs_offset, b_input.length);
                inputs_offset += b_input.length;
            }
            byte[] b6 = varint(BigInteger.valueOf(outputs.length));
            int outputs_length = 0;
            byte[][] b_outputs = new byte[outputs.length][];
            for (int i = 0; i < outputs.length; i++) {
                byte[] b_output = neoinout_output_encode(outputs[i], coin, testnet);
                b_outputs[i] = b_output;
                outputs_length += b_output.length;
            }
            byte[] b7 = new byte[outputs_length];
            int outputs_offset = 0;
            for (byte[] b_output : b_outputs) {
                System.arraycopy(b_output, 0, b7, outputs_offset, b_output.length);
                outputs_offset += b_output.length;
            }
            if (scripts == null) {
                return Bytes.concat(Bytes.concat(b1, b2, b3, b4, b5, b6), b7);
            }
            byte[] b8 = varint(BigInteger.valueOf(scripts.length));
            int scripts_length = 0;
            byte[][] b_scripts = new byte[scripts.length][];
            for (int i = 0; i < scripts.length; i++) {
                byte[] b_script = neoinout_script_encode(scripts[i]);
                b_scripts[i] = b_script;
                scripts_length += b_script.length;
            }
            byte[] b9 = new byte[scripts_length];
            int scripts_offset = 0;
            for (byte[] b_script : b_scripts) {
                System.arraycopy(b_script, 0, b9, scripts_offset, b_script.length);
                scripts_offset += b_script.length;
            }
            return Bytes.concat(Bytes.concat(b1, b2, b3, b4, b5, b6), b7, b8, b9);
        }
        if (fmt.equals("rlp")) {
            BigInteger nonce = fields.get("nonce", BigInteger.ZERO);
            BigInteger gasprice = fields.get("gasprice", BigInteger.ZERO);
            BigInteger gaslimit = fields.get("gaslimit", BigInteger.ZERO);
            String to = fields.get("to", null);
            BigInteger value = fields.get("value", BigInteger.ZERO);
            byte[] data = fields.get("data", new byte[]{ });
            byte[] v = fields.get("v", new byte[]{ });
            byte[] r = fields.get("r", new byte[]{ });
            byte[] s = fields.get("s", new byte[]{ });
            byte[] b = { };
            if (to != null) {
                Pair<BigInteger, String> t = Wallet.address_decode(to, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                b = Binint.n2b(h, 20);
            }
            boolean signed = v.length+r.length+s.length > 0;
            Object[] l = new Object[signed ? 9 : 6];
            l[0] = nlzint(nonce);
            l[1] = nlzint(gasprice);
            l[2] = nlzint(gaslimit);
            l[3] = b;
            l[4] = nlzint(value);
            l[5] = data;
            if (signed) {
                l[6] = nlzint(Binint.b2n(v));
                l[7] = nlzint(Binint.b2n(r));
                l[8] = nlzint(Binint.b2n(s));
            }
            return rlp(l);
        }
        if (fmt.equals("serial")) {
            BigInteger amount = fields.get("Amount", null);
            BigInteger fee = fields.get("Fee", null);
            String account = fields.get("Account", null);
            String destination = fields.get("Destination", null);
            String signingpubkey = fields.get("SigningPubKey", null);
            String txnsignature = fields.get("TxnSignature", null);
            if (amount != null) {
                amount = amount.or(BigInteger.ONE.shiftLeft(62));
            }
            if (fee != null) {
                fee = fee.or(BigInteger.ONE.shiftLeft(62));
            }
            byte[] b_account = null;
            if (account != null) {
                Pair<BigInteger, String> t = Wallet.address_decode(account, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                b_account = Binint.n2b(h, 20);
            }
            byte[] b_destination = null;
            if (destination != null) {
                Pair<BigInteger, String> t = Wallet.address_decode(destination, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                b_destination = Binint.n2b(h, 20);
            }
            byte[] b_signingpubkey = null;
            if (signingpubkey != null) {
                Pair<BigInteger[], Boolean> t = Wallet.publickey_decode(signingpubkey, coin, testnet);
                BigInteger[] P = t.l;
                boolean compressed = t.r;
                BigInteger x = P[0], y = P[1];
                boolean odd = y.and(BigInteger.ONE).equals(BigInteger.ONE);
                byte[] prefix = odd ? new byte[]{0x03} : new byte[]{0x02};
                byte[] b = Binint.n2b(x, 32);
                b_signingpubkey = Bytes.concat(prefix, b);
            }
            byte[] b_txnsignature = null;
            if (txnsignature != null) {
                b_txnsignature = Binint.h2b(txnsignature);
            }
            Dict f = new Dict(fields);
            if (amount != null) f.put("Amount", amount);
            if (fee != null) f.put("Fee", fee);
            if (b_account != null) f.put("Account", b_account);
            if (b_destination != null) f.put("Destination", b_destination);
            if (b_signingpubkey != null) f.put("SigningPubKey", b_signingpubkey);
            if (b_txnsignature != null) f.put("TxnSignature", b_txnsignature);
            return serial(f);
        }
        if (fmt.equals("xdr")) {
            String account = fields.get("Account");
            Pair<BigInteger, String> t = Wallet.address_decode(account, coin, testnet);
            BigInteger p = t.l;
            String kind = t.r;
            byte[] b_account = Binint.n2b(p, 32);
            BigInteger fee = fields.get("Fee");
            BigInteger sequence = fields.get("Sequence");
            Dict[] operations = fields.get("Operations");
            byte[] b_operations = new byte[]{};
            for (Dict operation : operations) {
                String optype = operation.get("Type");
                // TODO generalize
                if (optype.equals("CREATE_ACCOUNT")) {
                    String destination = operation.get("Destination");
                    Pair<BigInteger, String> _t = Wallet.address_decode(destination, coin, testnet);
                    BigInteger _p = _t.l;
                    String _kind = _t.r;
                    byte[] b_destination = Binint.n2b(_p, 32);
                    BigInteger amount = operation.get("Amount");
                    byte[] b1 = int32(BigInteger.ZERO, false); // source address count
                    byte[] b2 = int32(BigInteger.ZERO, false); // CREATE_ACCOUNT
                    byte[] b3 = int32(BigInteger.ZERO, false); // PUBLIC_KEY_TYPE_ED25519
                    byte[] b4 = b_destination;
                    byte[] b5 = int64(amount, false);
                    b_operations = Bytes.concat(b_operations, b1, b2, b3, b4, b5);
                }
                else
                if (optype.equals("PAYMENT")) {
                    String destination = operation.get("Destination");
                    Pair<BigInteger, String> _t = Wallet.address_decode(destination, coin, testnet);
                    BigInteger _p = _t.l;
                    String _kind = _t.r;
                    byte[] b_destination = Binint.n2b(_p, 32);
                    BigInteger amount = operation.get("Amount");
                    byte[] b1 = int32(BigInteger.ZERO, false); // source address count
                    byte[] b2 = int32(BigInteger.ONE, false); // PAYMENT
                    byte[] b3 = int32(BigInteger.ZERO, false); // PUBLIC_KEY_TYPE_ED25519
                    byte[] b4 = b_destination;
                    byte[] b5 = int32(BigInteger.ZERO, false); // ASSET_TYPE_NATIVE
                    byte[] b6 = int64(amount, false);
                    b_operations = Bytes.concat(b_operations, Bytes.concat(b1, b2, b3, b4, b5, b6));
                }
                else {
                    throw new IllegalArgumentException("Unsupported operation type");
                }
            }
            byte[] sigs = new byte[]{ };
            if (fields.has("Signatures")) {
                Dict[] signatures = fields.get("Signatures");
                sigs = int32(BigInteger.valueOf(signatures.length), false);
                for (Dict sigobject : signatures) {
                    byte[] hint = sigobject.get("Hint");
                    byte[] signature = sigobject.get("Signature");
                    byte[] len_signature = int32(BigInteger.valueOf(signature.length), false);
                    sigs = Bytes.concat(sigs, hint, len_signature, signature);
                }
            }
            byte[] b1 = int32(BigInteger.ZERO, false); // PUBLIC_KEY_TYPE_ED25519
            byte[] b2 = b_account;
            byte[] b3 = int32(fee, false);
            byte[] b4 = int64(sequence, false);
            byte[] b5 = int32(BigInteger.ZERO, false); // time bounds count
            byte[] b6 = int32(BigInteger.ZERO, false); // MEMO_NONE
            byte[] b7 = int32(BigInteger.valueOf(operations.length), false);
            byte[] b8 = b_operations;
            byte[] b9 = int32(BigInteger.ZERO, false);
            byte[] b10 = sigs;
            return Bytes.concat(Bytes.concat(b1, b2, b3, b4, b5, b6), Bytes.concat(b7, b8, b9, b10));
        }
        if (fmt.equals("raiblock")) {
            BigInteger preamble = BigInteger.valueOf(6);
            String account = fields.get("account");
            String previous = fields.get("previous", Binint.n2h(BigInteger.ZERO, 32));
            String representative = fields.get("representative");
            BigInteger balance = fields.get("balance");
            String link = fields.get("link", Binint.n2h(BigInteger.ZERO, 32));
            byte[] signature = fields.get("signature", new byte[]{});
            byte[] work = fields.get("work", new byte[]{});
            Pair<BigInteger, String> t = Wallet.address_decode(account, coin, testnet);
            BigInteger a = t.l;
            String kind = t.r;
            t = Wallet.address_decode(representative, coin, testnet);
            BigInteger r = t.l;
            kind = t.r;
            byte[] b1 = Binint.n2b(preamble, 32);
            byte[] b2 = Binint.n2b(a, 32);
            byte[] b3 = Binint.h2b(previous);
            byte[] b4 = Binint.n2b(r, 32);
            byte[] b5 = Binint.n2b(balance, 16);
            byte[] b6 = Binint.h2b(link);
            byte[] b7 = signature;
            byte[] b8 = work;
            return Bytes.concat(Bytes.concat(b1, b2, b3, b4, b5, b6), b7, b8);
        }
        if (fmt.equals("liskdatablock")) {
            BigInteger txtype = BigInteger.ZERO; // transmit
            BigInteger timestamp = fields.get("timestamp");
            String publickey = fields.get("publickey", "");
            String recipient = fields.get("recipient");
            BigInteger amount = fields.get("amount");
            byte[] signature = fields.get("signature", new byte[]{});
            Pair<BigInteger, String> t = Wallet.address_decode(recipient, coin, testnet);
            BigInteger r = t.l;
            String kind = t.r;
            byte[] b1 = Binint.n2b(txtype, 1);
            byte[] b2 = Bytes.rev(Binint.n2b(timestamp, 4));
            byte[] b3 = Binint.h2b(publickey);
            byte[] b4 = Binint.n2b(r, 8);
            byte[] b5 = Bytes.rev(Binint.n2b(amount, 8));
            byte[] b6 = signature;
            return Bytes.concat(b1, b2, b3, b4, b5, b6);
        }
        if (fmt.equals("wavestx")) {
            int txtype = 4;
            BigInteger version = fields.get("version", BigInteger.valueOf(1));
            String publickey = fields.get("publickey", null);
            String asset = fields.get("asset", null);
            String fee_asset = fields.get("fee_asset", null);
            BigInteger timestamp = fields.get("timestamp");
            BigInteger amount = fields.get("amount");
            BigInteger fee = fields.get("fee");
            String recipient = fields.get("recipient");
            String attachment = fields.get("attachment", null);
            byte[] b_signature = fields.get("signature", new byte[]{});
            byte[] b_publickey = publickey != null ? Base58.decode(publickey) : new byte[32];
            byte[] b_asset = asset != null ? Bytes.concat(new byte[]{1}, Base58.decode(asset)) : new byte[]{0};
            byte[] b_fee_asset = fee_asset != null ? Bytes.concat(new byte[]{1}, Base58.decode(fee_asset)) : new byte[]{0};
            byte[] b_recipient = Base58.decode(recipient);
            byte[] b_attachment = attachment != null ? Base58.decode(attachment) : new byte[]{};
            byte[] b0 = Binint.n2b(version, 1);
            byte[] b1 = Binint.n2b(BigInteger.valueOf(txtype), 1);
            byte[] b2 = version.compareTo(BigInteger.ONE) > 0 ? Binint.n2b(version, 1) : new byte[]{};
            byte[] b3 = b_publickey;
            byte[] b4 = b_asset;
            byte[] b5 = b_fee_asset;
            byte[] b6 = Binint.n2b(timestamp, 8);
            byte[] b7 = Binint.n2b(amount, 8);
            byte[] b8 = Binint.n2b(fee, 8);
            byte[] b9 = b_recipient;
            byte[] b10 = Binint.n2b(BigInteger.valueOf(b_attachment.length), 2);
            byte[] b11 = b_attachment;
            byte[] b12 = b_signature;
            return Bytes.concat(b0, Bytes.concat(b1, b2, b3, b4, b5, b6), Bytes.concat(b7, b8, b9, b10, b11, b12));
        }
        if (fmt.equals("cbor")) {
            Dict[] ins = fields.get("inputs");
            List<Object> inputs = new ArrayList<>();
            for (Dict in : ins) {
                String txnid = in.get("txnid");
                BigInteger index = in.get("index", BigInteger.ZERO);
                Object pair = new Object[]{Binint.h2b(txnid), index};
                Object item = new Object[]{BigInteger.ZERO, new Cbor.Tag(BigInteger.valueOf(24), Cbor.dumps(pair))};
                inputs.add(item);
            }
            Dict[] outs = fields.get("outputs");
            List<Object> outputs = new ArrayList<>();
            for (Dict out : outs) {
                BigInteger amount = out.get("amount", BigInteger.ZERO);
                String address = out.get("address");
                Object struct = Cbor.loads(Base58.decode(address));
                Object item = new Object[]{struct, amount};
                outputs.add(item);
            }
            Object data = new Object[]{ inputs, outputs, new HashMap<>() };
            if (fields.has("witnesses")) {
                Dict[] wits = fields.get("witnesses");
                Object[] witnesses = new Object[wits.length];
                for (int i = 0; i < wits.length; i++) {
                    Dict wit = wits[i];
                    String publickey = wit.get("publickey");
                    String chaincode = wit.get("chaincode");
                    byte[] signature = wit.get("signature");
                    Object pair = new Object[]{Binint.h2b(publickey + chaincode), signature};
                    Object item = new Object[]{BigInteger.ZERO, new Cbor.Tag(BigInteger.valueOf(24), Cbor.dumps(pair))};
                    witnesses[i] = item;
                }
                data = new Object[]{ data, witnesses };
            }
            return Cbor.dumps(data);
        }
        if (fmt.equals("protobuf")) {
            Pair<BigInteger, String> r1 = Wallet.address_decode(fields.get("owner_address"), coin, testnet);
            BigInteger h1 = r1.l;
            String kind1 = r1.r;
            byte[] prefix1 = Coins.attr(kind1 + ".base58.prefix", coin, testnet);
            Pair<BigInteger, String> r2 = Wallet.address_decode(fields.get("to_address"), coin, testnet);
            BigInteger h2 = r2.l;
            String kind2 = r2.r;
            byte[] prefix2 = Coins.attr(kind2 + ".base58.prefix", coin, testnet);
            Map<Integer, Object> message_params = new HashMap<>();
            message_params.put(1, Bytes.concat(prefix1, Binint.n2b(h1, 20)));
            message_params.put(2, Bytes.concat(prefix2, Binint.n2b(h2, 20)));
            message_params.put(3, fields.get("amount"));
            Map<Integer, Object> message = new HashMap<>();
            message.put(1, "type.googleapis.com/protocol.TransferContract".getBytes());
            message.put(2, message_params);
            Map<Integer, Object> contract = new HashMap<>();
            contract.put(1, BigInteger.ONE);
            contract.put(2, message);
            Map<Integer, Object> data = new HashMap<>();
            data.put(1, fields.get("ref_block_bytes"));
            data.put(4, fields.get("ref_block_hash"));
            data.put(8, fields.get("expiration"));
            data.put(11, contract);
            if (fields.has("signature")) {
                Map<Integer, Object> signed_data = new HashMap<>();
                signed_data.put(1, data);
                signed_data.put(2, fields.get("signature"));
                data = signed_data;
            }
            return Protobuf.dumps(data);
        }
        throw new IllegalStateException("Unknown format");
    }

    private static Pair<Dict, byte[]> inout_input_decode(byte[] txn) {
        int size1 = 32;
        if (size1 > txn.length) throw new IllegalArgumentException("End of input");
        byte[] b1 = Bytes.sub(txn, 0, size1);
        byte[] t = Bytes.sub(txn, size1);
        r(b1);
        String txnid = Binint.b2h(b1);
        txn = t;
        Pair<BigInteger, byte[]> r1 = parse_int32(txn);
        BigInteger index = r1.l;
        txn = r1.r;
        Pair<BigInteger, byte[]> r2 = parse_varint(txn);
        int size2 = r2.l.intValue();
        txn = r2.r;
        if (size2 > txn.length) throw new IllegalArgumentException("End of input");
        byte[] inscript = Bytes.sub(txn, 0, size2);
        byte[] b2 = Bytes.sub(txn, size2);
        txn = b2;
        Pair<BigInteger, byte[]> r3 = parse_int32(txn);
        BigInteger sequence = r3.l;
        txn = r3.r;
        Dict fields = new Dict();
        fields.put("txnid", txnid);
        fields.put("index", index);
        fields.put("script", inscript);
        fields.put("sequence", sequence);
        return new Pair<>(fields, txn);
    }

    private static Pair<Dict, byte[]> inout_output_decode(byte[] txn) {
        Pair<BigInteger, byte[]> r1 = parse_int64(txn);
        BigInteger amount = r1.l;
        txn = r1.r;
        Pair<BigInteger, byte[]> r2 = parse_varint(txn);
        int size = r2.l.intValue();
        txn = r2.r;
        if (size > txn.length) throw new IllegalArgumentException("End of input");
        byte[] outscript = Bytes.sub(txn, 0, size);
        byte[] b = Bytes.sub(txn, size);
        txn = b;
        Dict fields = new Dict();
        fields.put("amount", amount);
        fields.put("script", outscript);
        return new Pair<>(fields, txn);
    }

    private static Pair<Dict, byte[]> dcrinout_input_decode(byte[] txn) {
        int size1 = 32;
        if (size1 > txn.length) throw new IllegalArgumentException("End of input");
        String txnid = Binint.b2h(Bytes.rev(Bytes.sub(txn, 0, size1)));
        txn = Bytes.sub(txn, size1);
        Pair<BigInteger, byte[]> r1 = parse_int32(txn);
        BigInteger index = r1.l;
        txn = r1.r;
        Pair<BigInteger, byte[]> r2 = parse_int8(txn);
        BigInteger tree = r2.l;
        txn = r2.r;
        Pair<BigInteger, byte[]> r3 = parse_int32(txn);
        BigInteger sequence = r3.l;
        txn = r3.r;
        Dict fields = new Dict();
        fields.put("txnid", txnid);
        fields.put("index", index);
        fields.put("tree", tree);
        fields.put("sequence", sequence);
        return new Pair<>(fields, txn);
    }

    private static Pair<Dict, byte[]> dcrinout_output_decode(byte[] txn) {
        Pair<BigInteger, byte[]> r1 = parse_int64(txn);
        BigInteger amount = r1.l;
        txn = r1.r;
        Pair<BigInteger, byte[]> r2 = parse_int16(txn);
        BigInteger version = r2.l;
        txn = r2.r;
        Pair<BigInteger, byte[]> r3 = parse_varint(txn);
        int size = r3.l.intValue();
        txn = r3.r;
        if (size > txn.length) throw new IllegalArgumentException("End of input");
        byte[] outscript = Bytes.sub(txn, 0, size);
        txn = Bytes.sub(txn, size);
        Dict fields = new Dict();
        fields.put("amount", amount);
        fields.put("version", version);
        fields.put("script", outscript);
        return new Pair<>(fields, txn);
    }

    private static Pair<Dict, byte[]> dcrinout_witness_decode(byte[] txn) {
        Pair<BigInteger, byte[]> r1 = parse_int64(txn);
        BigInteger amount = r1.l;
        txn = r1.r;
        Pair<BigInteger, byte[]> r2 = parse_int32(txn);
        BigInteger blockheight = r2.l;
        txn = r2.r;
        Pair<BigInteger, byte[]> r3 = parse_int32(txn);
        BigInteger blockindex = r3.l;
        txn = r3.r;
        Pair<BigInteger, byte[]> r4 = parse_varint(txn);
        int size4 = r4.l.intValue();
        txn = r4.r;
        if (size4 > txn.length) throw new IllegalArgumentException("End of input");
        byte[] inscript = Bytes.sub(txn, 0, size4);
        txn = Bytes.sub(txn, size4);
        Dict fields = new Dict();
        fields.put("amount", amount);
        fields.put("blockheight", blockheight);
        fields.put("blockindex", blockindex);
        fields.put("script", inscript);
        return new Pair<>(fields, txn);
    }

    private static Pair<Dict, byte[]> neoinout_input_decode(byte[] txn) {
        int size = 32;
        if (size > txn.length) throw new IllegalArgumentException("End of input");
        String txnid = Binint.b2h(Bytes.rev(Bytes.sub(txn, 0, size)));
        txn = Bytes.sub(txn, size);
        Pair<BigInteger, byte[]> t = parse_int16(txn);
        BigInteger index = t.l;
        txn = t.r;
        Dict fields = new Dict();
        fields.put("txnid", txnid);
        fields.put("index", index);
        return new Pair<>(fields, txn);
    }

    private static Pair<Dict, byte[]> neoinout_output_decode(byte[] txn, String coin, boolean testnet) {
        int asset_size = 32;
        if (asset_size > txn.length) throw new IllegalArgumentException("End of input");
        String asset = Binint.b2h(Bytes.rev(Bytes.sub(txn, 0, asset_size)));
        txn = Bytes.sub(txn, asset_size);
        Pair<BigInteger, byte[]> t = parse_int64(txn);
        BigInteger amount = t.l;
        txn = t.r;
        int address_size = 20;
        if (address_size > txn.length) throw new IllegalArgumentException("End of input");
        BigInteger h = Binint.b2n(Bytes.sub(txn, 0, address_size));
        txn = Bytes.sub(txn, address_size);
        String address = Wallet.address_encode(h, "address", coin, testnet);
        Dict fields = new Dict();
        fields.put("asset", asset);
        fields.put("amount", amount);
        fields.put("address", address);
        return new Pair<>(fields, txn);
    }

    private static Pair<Dict, byte[]> neoinout_script_decode(byte[] txn) {
        Pair<BigInteger, byte[]> r1 = parse_varint(txn);
        int invocation_size = r1.l.intValue();
        txn = r1.r;
        if (invocation_size > txn.length) throw new IllegalArgumentException("End of input");
        byte[] invocation_script = Bytes.sub(txn, 0, invocation_size);
        txn = Bytes.sub(txn, invocation_size);
        Pair<BigInteger, byte[]> r2 = parse_varint(txn);
        int verification_size = r2.l.intValue();
        txn = r2.r;
        if (verification_size > txn.length) throw new IllegalArgumentException("End of input");
        byte[] verification_script = Bytes.sub(txn, 0, verification_size);
        txn = Bytes.sub(txn, verification_size);
        Dict fields = new Dict();
        fields.put("invocation", invocation_script);
        fields.put("verification", verification_script);
        return new Pair<>(fields, txn);
    }

    public static Dict transaction_decode(byte[] txn, String coin, boolean testnet) {
        String fmt = Coins.attr("transaction.format", coin, testnet);
        if (fmt.equals("inout")) {
            Pair<BigInteger, byte[]> r1 = parse_int32(txn);
            BigInteger version = r1.l;
            txn = r1.r;
            BigInteger groupid = null;
            if (version.equals(BigInteger.valueOf(0x080000004L))) { // zcash sapling
                Pair<BigInteger, byte[]> r2 = parse_int32(txn);
                groupid = r2.l;
                txn = r2.r;
            }
            Pair<BigInteger, byte[]> r2 = parse_varint(txn);
            int input_count = r2.l.intValue();
            txn = r2.r;
            Dict[] inputs = new Dict[input_count];
            for (int i = 0; i < inputs.length; i++) {
                Pair<Dict, byte[]> r3 = inout_input_decode(txn);
                Dict fields = r3.l;
                txn = r3.r;
                inputs[i] = fields;
            }
            Pair<BigInteger, byte[]> r3 = parse_varint(txn);
            int output_count = r3.l.intValue();
            txn = r3.r;
            Dict[] outputs = new Dict[output_count];
            for (int i = 0; i < outputs.length; i++) {
                Pair<Dict, byte[]> r4 = inout_output_decode(txn);
                Dict fields = r4.l;
                txn = r4.r;
                outputs[i] = fields;
            }
            Pair<BigInteger, byte[]> r4 = parse_int32(txn);
            BigInteger locktime = r4.l;
            txn = r4.r;
            BigInteger expiryheight = null;
            if (version.equals(BigInteger.valueOf(0x080000004L))) { // zcash sapling
                Pair<BigInteger, byte[]> r5 = parse_int32(txn);
                expiryheight = r5.l;
                txn = r5.r;
                Pair<BigInteger, byte[]> r6 = parse_int64(txn);
                BigInteger valuebalance = r6.l;
                txn = r6.r;
                if (!valuebalance.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
                Pair<BigInteger, byte[]> r7 = parse_varint(txn);
                BigInteger vshieldedspend = r7.l;
                txn = r7.r;
                if (!vshieldedspend.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
                Pair<BigInteger, byte[]> r8 = parse_varint(txn);
                BigInteger vshieldedoutput = r8.l;
                txn = r8.r;
                if (!vshieldedoutput.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
                Pair<BigInteger, byte[]> r9 = parse_varint(txn);
                BigInteger vjoinsplit = r9.l;
                txn = r9.r;
                if (!vjoinsplit.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
            }
            if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            Dict fields = new Dict();
            fields.put("version", version);
            if (groupid != null) fields.put("groupid", groupid);
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            fields.put("locktime", locktime);
            if (expiryheight != null) fields.put("expiryheight", expiryheight);
            return fields;
        }
        if (fmt.equals("dcrinout")) {
            Pair<BigInteger, byte[]> r1 = parse_int32(txn);
            BigInteger version = r1.l;
            txn = r1.r;
            Pair<BigInteger, byte[]> r2 = parse_varint(txn);
            int input_count = r2.l.intValue();
            txn = r2.r;
            Dict[] inputs = new Dict[input_count];
            for (int i = 0; i < inputs.length; i++) {
                Pair<Dict, byte[]> r3 = dcrinout_input_decode(txn);
                Dict fields = r3.l;
                txn = r3.r;
                inputs[i] = fields;
            }
            Pair<BigInteger, byte[]> r3 = parse_varint(txn);
            int output_count = r3.l.intValue();
            txn = r3.r;
            Dict[] outputs = new Dict[output_count];
            for (int i = 0; i < outputs.length; i++) {
                Pair<Dict, byte[]> r4 = dcrinout_output_decode(txn);
                Dict fields = r4.l;
                txn = r4.r;
                outputs[i] = fields;
            }
            Pair<BigInteger, byte[]> r4 = parse_int32(txn);
            BigInteger locktime = r4.l;
            txn = r4.r;
            Pair<BigInteger, byte[]> r5 = parse_int32(txn);
            BigInteger expiryheight = r5.l;
            txn = r5.r;
            Dict[] witnesses = null;
            if (txn.length > 0) {
                Pair<BigInteger, byte[]> r6 = parse_varint(txn);
                int witness_count = r6.l.intValue();
                txn = r6.r;
                witnesses = new Dict[witness_count];
                for (int i = 0; i < witnesses.length; i++) {
                    Pair<Dict, byte[]> r7 = dcrinout_witness_decode(txn);
                    Dict fields = r7.l;
                    txn = r7.r;
                    witnesses[i] = fields;
                }
            }
            if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            Dict fields = new Dict();
            fields.put("version", version);
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            fields.put("locktime", locktime);
            fields.put("expiryheight", expiryheight);
            fields.put("witnesses", witnesses);
            return fields;
        }
        if (fmt.equals("neoinout")) {
            Pair<BigInteger, byte[]> r1 = parse_int8(txn);
            BigInteger txtype = r1.l;
            txn = r1.r;
            if (!txtype.equals(BigInteger.valueOf(0x80))) throw new IllegalArgumentException("Invalid transaction");
            Pair<BigInteger, byte[]> r2 = parse_int8(txn);
            BigInteger version = r2.l;
            txn = r2.r;
            if (!version.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid transaction");
            Pair<BigInteger, byte[]> r3 = parse_varint(txn);
            int attr_count = r3.l.intValue();
            txn = r3.r;
            if (attr_count != 0) throw new IllegalArgumentException("Unsupported attributes");
            Pair<BigInteger, byte[]> r4 = parse_varint(txn);
            int input_count = r4.l.intValue();
            txn = r4.r;
            Dict[] inputs = new Dict[input_count];
            for (int i = 0; i < inputs.length; i++) {
                Pair<Dict, byte[]> r5 = neoinout_input_decode(txn);
                Dict fields = r5.l;
                txn = r5.r;
                inputs[i] = fields;
            }
            Pair<BigInteger, byte[]> r6 = parse_varint(txn);
            int output_count = r6.l.intValue();
            txn = r6.r;
            Dict[] outputs = new Dict[output_count];
            for (int i = 0; i < outputs.length; i++) {
                Pair<Dict, byte[]> r7 = neoinout_output_decode(txn, coin, testnet);
                Dict fields = r7.l;
                txn = r7.r;
                outputs[i] = fields;
            }
            if (txn.length == 0) {
                Dict fields = new Dict();
                fields.put("type", txtype);
                fields.put("version", version);
                fields.put("inputs", inputs);
                fields.put("outputs", outputs);
                return fields;
            }
            Pair<BigInteger, byte[]> r8 = parse_varint(txn);
            int script_count = r8.l.intValue();
            txn = r8.r;
            Dict[] scripts = new Dict[script_count];
            for (int i = 0; i < scripts.length; i++) {
                Pair<Dict, byte[]> r7 = neoinout_script_decode(txn);
                Dict fields = r7.l;
                txn = r7.r;
                scripts[i] = fields;
            }
            if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            Dict fields = new Dict();
            fields.put("type", txtype);
            fields.put("version", version);
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            fields.put("scripts", scripts);
            return fields;
        }
        if (fmt.equals("rlp")) {
            Pair<Object, byte[]> r = parse_rlp(txn);
            Object o = r.l;
            txn = r.r;
            if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            if (!(o instanceof Object[])) throw new IllegalArgumentException("Invalid transaction");
            Object[] l = (Object[]) o;
            if (l.length != 6 && l.length != 9) throw new IllegalArgumentException("Invalid transaction");
            Dict fields = new Dict();
            fields.put("nonce", parse_nlzint((byte[]) l[0]).l);
            fields.put("gasprice", parse_nlzint((byte[]) l[1]).l);
            fields.put("gaslimit", parse_nlzint((byte[]) l[2]).l);
            byte[] b = (byte[]) l[3];
            if (b.length > 0) {
                if (b.length != 20) throw new IllegalArgumentException("Invalid transaction");
                BigInteger h = Binint.b2n(b);
                fields.put("to", Wallet.address_encode(h, "address", coin, testnet));
            }
            fields.put("value", parse_nlzint((byte[]) l[4]).l);
            fields.put("data", l[5]);
            if (l.length > 6) {
                fields.put("v", Binint.n2b(parse_nlzint((byte[]) l[6]).l, 1));
                fields.put("r", Binint.n2b(parse_nlzint((byte[]) l[7]).l, 32));
                fields.put("s", Binint.n2b(parse_nlzint((byte[]) l[8]).l, 32));
            }
            return fields;
        }
        if (fmt.equals("serial")) {
            Dict fields = parse_serial(txn);
            BigInteger amount = fields.get("Amount", null);
            BigInteger fee = fields.get("Fee", null);
            byte[] b_account = fields.get("Account", null);
            byte[] b_destination = fields.get("Destination", null);
            byte[] b_signingpubkey = fields.get("SigningPubKey", null);
            byte[] b_txnsignature = fields.get("TxnSignature", null);
            if (amount != null) {
                amount = amount.subtract(BigInteger.ONE.shiftLeft(62));
            }
            if (fee != null) {
                fee = fee.subtract(BigInteger.ONE.shiftLeft(62));
            }
            String account = null;
            if (b_account != null) {
                BigInteger h = Binint.b2n(b_account);
                account = Wallet.address_encode(h, "address", coin, testnet);
            }
            String destination = null;
            if (b_destination != null) {
                BigInteger h = Binint.b2n(b_destination);
                destination = Wallet.address_encode(h, "address", coin, testnet);
            }
            String signingpubkey = null;
            if (b_signingpubkey != null) {
                byte prefix = b_signingpubkey[0];
                byte[] b = new byte[b_signingpubkey.length - 1];
                System.arraycopy(b_signingpubkey, 1, b, 0, b.length);
                if (prefix != 0x02 && prefix != 0x03) throw new IllegalArgumentException("Invalid prefix");
                boolean odd = prefix != 0x02;
                BigInteger x = Binint.b2n(b);
                BigInteger y = Secp256k1.fnd(x, odd);
                BigInteger[] P = new BigInteger[]{x, y};
                signingpubkey = Wallet.publickey_encode(P, true, coin, testnet);
            }
            String txnsignature = null;
            if (b_txnsignature != null) {
                txnsignature = Binint.b2h(b_txnsignature);
            }
            if (amount != null) fields.put("Amount", amount);
            if (fee != null) fields.put("Fee", fee);
            if (account != null) fields.put("Account", account);
            if (destination != null) fields.put("Destination", destination);
            if (signingpubkey != null) fields.put("SigningPubKey", signingpubkey);
            if (txnsignature != null) fields.put("TxnSignature", txnsignature);
            return fields;
        }
        if (fmt.equals("xdr")) {
            Pair<BigInteger, byte[]> t = parse_int32(txn, false);
            BigInteger keytype = t.l;
            txn = t.r;
            if (!keytype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported keytype");
            if (32 > txn.length) throw new IllegalArgumentException("End of input");
            BigInteger h = Binint.b2n(Bytes.sub(txn, 0, 32));
            txn = Bytes.sub(txn, 32);
            String account = Wallet.address_encode(h, "address", coin, testnet);
            t = parse_int32(txn, false);
            BigInteger fee = t.l;
            txn = t.r;
            t = parse_int64(txn, false);
            BigInteger sequence = t.l;
            txn = t.r;
            t = parse_int32(txn, false);
            BigInteger count = t.l;
            txn = t.r;
            if (!count.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported time bounds count");
            t = parse_int32(txn, false);
            BigInteger memotype = t.l;
            txn = t.r;
            if (!memotype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported memo type");
            t = parse_int32(txn, false);
            count = t.l;
            txn = t.r;
            Dict[] operations = new Dict[count.intValue()];
            for (int i = 0; i < operations.length; i++) {
                Dict operation = new Dict();
                // TODO generalize
                t = parse_int32(txn, false);
                count = t.l;
                txn = t.r;
                if (!count.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported sources count");
                t = parse_int32(txn, false);
                BigInteger optype = t.l;
                txn = t.r;
                if (optype.equals(BigInteger.ZERO)) {
                    t = parse_int32(txn, false);
                    keytype = t.l;
                    txn = t.r;
                    if (!keytype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported keytype");
                    if (32 > txn.length) throw new IllegalArgumentException("End of input");
                    h = Binint.b2n(Bytes.sub(txn, 0, 32));
                    txn = Bytes.sub(txn, 32);
                    String destination = Wallet.address_encode(h, "address", coin, testnet);
                    t = parse_int64(txn, false);
                    BigInteger amount = t.l;
                    txn = t.r;
                    operation.put("Type", "CREATE_ACCOUNT");
                    operation.put("Destination", destination);
                    operation.put("Amount", amount);
                }
                else
                if (optype.equals(BigInteger.ONE)) {
                    t = parse_int32(txn, false);
                    keytype = t.l;
                    txn = t.r;
                    if (!keytype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported keytype");
                    if (32 > txn.length) throw new IllegalArgumentException("End of input");
                    h = Binint.b2n(Bytes.sub(txn, 0, 32));
                    txn = Bytes.sub(txn, 32);
                    String destination = Wallet.address_encode(h, "address", coin, testnet);
                    t = parse_int32(txn, false);
                    BigInteger assettype = t.l;
                    txn = t.r;
                    if (!assettype.equals(BigInteger.ZERO))
                        throw new IllegalArgumentException("Unsupported asset type");
                    t = parse_int64(txn, false);
                    BigInteger amount = t.l;
                    txn = t.r;
                    operation.put("Type", "PAYMENT");
                    operation.put("Destination", destination);
                    operation.put("Amount", amount);
                }
                else {
                    throw new IllegalArgumentException("Unsupported operation type");
                }
                operations[i] = operation;
            }
            t = parse_int32(txn, false);
            BigInteger flag = t.l;
            txn = t.r;
            if (!flag.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Unsupported flag");
            Dict fields = new Dict();
            fields.put("Account", account);
            fields.put("Fee", fee);
            fields.put("Sequence", sequence);
            fields.put("Operations", operations);
            if (txn.length > 0) {
                t = parse_int32(txn, false);
                count = t.l;
                txn = t.r;
                Dict[] signatures = new Dict[count.intValue()];
                for (int i = 0; i < signatures.length; i++) {
                    if (4 > txn.length) throw new IllegalArgumentException("End of input");
                    byte[] hint = Bytes.sub(txn, 0, 4);
                    txn = Bytes.sub(txn, 4);
                    t = parse_int32(txn, false);
                    BigInteger size = t.l;
                    txn = t.r;
                    if (size.intValue() != 64) throw new IllegalArgumentException("Invalid signature size");
                    if (64 > txn.length) throw new IllegalArgumentException("End of input");
                    byte[] signature = Bytes.sub(txn, 0, 64);
                    txn = Bytes.sub(txn, 64);
                    Dict sigobject = new Dict();
                    sigobject.put("Hint", hint);
                    sigobject.put("Signature", signature);
                    signatures[i] = sigobject;
                }
                fields.put("Signatures", signatures);
                if (txn.length != 0) throw new IllegalArgumentException("Invalid transaction");
            }
            return fields;
        }
        if (fmt.equals("raiblock")) {
            if (txn.length != 176 && txn.length != 184 && txn.length != 240 && txn.length != 248)
                throw new IllegalArgumentException("Invalid transaction");
            BigInteger preamble = Binint.b2n(Bytes.sub(txn, 0, 32));
            txn = Bytes.sub(txn, 32);
            BigInteger a = Binint.b2n(Bytes.sub(txn, 0, 32));
            txn = Bytes.sub(txn, 32);
            String previous = Binint.b2h(Bytes.sub(txn, 0, 32));
            txn = Bytes.sub(txn, 32);
            BigInteger r = Binint.b2n(Bytes.sub(txn, 0, 32));
            txn = Bytes.sub(txn, 32);
            BigInteger balance = Binint.b2n(Bytes.sub(txn, 0, 16));
            txn = Bytes.sub(txn, 16);
            String link = Binint.b2h(Bytes.sub(txn, 0, 32));
            txn = Bytes.sub(txn, 32);
            if (!preamble.equals(BigInteger.valueOf(6))) throw new IllegalArgumentException("Invalid preamble");
            String account = Wallet.address_encode(a, "address", coin, testnet);
            String representative = Wallet.address_encode(r, "address", coin, testnet);
            Dict fields = new Dict();
            fields.put("account", account);
            fields.put("previous", previous);
            fields.put("representative", representative);
            fields.put("balance", balance);
            fields.put("link", link);
            if (txn.length >= 64) {
                byte[] signature = Bytes.sub(txn, 0, 64);
                txn = Bytes.sub(txn, 64);
                fields.put("signature", signature);
            }
            if (txn.length >= 8) {
                byte[] work = Bytes.sub(txn, 0, 8);
                txn = Bytes.sub(txn, 8);
                fields.put("work", work);
            }
            assert txn.length == 0;
            return fields;
        }
        if (fmt.equals("liskdatablock")) {
            if (txn.length != 21 && txn.length != 53 && txn.length != 85 && txn.length != 117)
                throw new IllegalArgumentException("Invalid transaction");
            BigInteger txtype = Binint.b2n(Bytes.sub(txn, 0, 1));
            txn = Bytes.sub(txn, 1);
            BigInteger timestamp = Binint.b2n(Bytes.rev(Bytes.sub(txn, 0, 4)));
            txn = Bytes.sub(txn, 4);
            String publickey = null;
            if (txn.length == 48 || txn.length == 112) {
                publickey = Binint.b2h(Bytes.sub(txn, 0, 32));
                txn = Bytes.sub(txn, 32);
            }
            BigInteger r = Binint.b2n(Bytes.sub(txn, 0, 8));
            txn = Bytes.sub(txn, 8);
            BigInteger amount = Binint.b2n(Bytes.rev(Bytes.sub(txn, 0, 8)));
            txn = Bytes.sub(txn, 8);
            if (!txtype.equals(BigInteger.ZERO)) throw new IllegalArgumentException("Invalid type");
            String recipient = Wallet.address_encode(r, "address", coin, testnet);
            Dict fields = new Dict();
            fields.put("timestamp", timestamp);
            fields.put("recipient", recipient);
            fields.put("amount", amount);
            if (publickey != null) fields.put("publickey", publickey);
            if (txn.length >= 64) {
                byte[] signature = Bytes.sub(txn, 0, 64);
                txn = Bytes.sub(txn, 64);
                fields.put("signature", signature);
            }
            assert txn.length == 0;
            return fields;
        }
        if (fmt.equals("wavestx")) {
            if (txn.length < 1) throw new IllegalArgumentException("End of input");
            BigInteger version = Binint.b2n(Bytes.sub(txn, 0, 1));
            txn = Bytes.sub(txn, 1);
            if (txn.length < 1) throw new IllegalArgumentException("End of input");
            int txtype = Binint.b2n(Bytes.sub(txn, 0, 1)).intValue();
            txn = Bytes.sub(txn, 1);
            if (txtype != 4) throw new IllegalArgumentException("Invalid type");
            if (version.compareTo(BigInteger.ONE) > 0) {
                if (txn.length < 1) throw new IllegalArgumentException("End of input");
                version = Binint.b2n(Bytes.sub(txn, 0, 1));
                txn = Bytes.sub(txn, 1);
            }
            if (version.compareTo(BigInteger.valueOf(2)) > 0) throw new IllegalArgumentException("Invalid version");
            if (txn.length < 32) throw new IllegalArgumentException("End of input");
            byte[] b_publickey = Bytes.sub(txn, 0, 32);
            txn = Bytes.sub(txn, 32);
            String publickey = Bytes.equ(b_publickey, new byte[32]) ? null : Base58.encode(b_publickey);
            if (txn.length < 1) throw new IllegalArgumentException("End of input");
            int has_asset = Binint.b2n(Bytes.sub(txn, 0, 1)).intValue();
            txn = Bytes.sub(txn, 1);
            if (has_asset > 1) throw new IllegalArgumentException("Invalid asset marker");
            String asset = null;
            if (has_asset == 1) {
                if (txn.length < 32) throw new IllegalArgumentException("End of input");
                asset = Base58.encode(Bytes.sub(txn, 0, 32));
                txn = Bytes.sub(txn, 32);
            }
            if (txn.length < 1) throw new IllegalArgumentException("End of input");
            int has_fee_asset = Binint.b2n(Bytes.sub(txn, 0, 1)).intValue();
            txn = Bytes.sub(txn, 1);
            if (has_fee_asset > 1) throw new IllegalArgumentException("Invalid asset marker");
            String fee_asset = null;
            if (has_fee_asset == 1) {
                if (txn.length < 32) throw new IllegalArgumentException("End of input");
                fee_asset = Base58.encode(Bytes.sub(txn, 0, 32));
                txn = Bytes.sub(txn, 32);
            }
            if (txn.length < 8) throw new IllegalArgumentException("End of input");
            BigInteger timestamp = Binint.b2n(Bytes.sub(txn, 0, 8));
            txn = Bytes.sub(txn, 8);
            if (txn.length < 8) throw new IllegalArgumentException("End of input");
            BigInteger amount = Binint.b2n(Bytes.sub(txn, 0, 8));
            txn = Bytes.sub(txn, 8);
            if (txn.length < 8) throw new IllegalArgumentException("End of input");
            BigInteger fee = Binint.b2n(Bytes.sub(txn, 0, 8));
            txn = Bytes.sub(txn, 8);
            if (txn.length < 26) throw new IllegalArgumentException("End of input");
            String recipient = Base58.encode(Bytes.sub(txn, 0, 26));
            txn = Bytes.sub(txn, 26);
            if (txn.length < 2) throw new IllegalArgumentException("End of input");
            int size = Binint.b2n(Bytes.sub(txn, 0, 2)).intValue();
            txn = Bytes.sub(txn, 2);
            if (txn.length < size) throw new IllegalArgumentException("End of input");
            String attachment = Base58.encode(Bytes.sub(txn, 0, size));
            txn = Bytes.sub(txn, size);
            byte[] signature = null;
            if (txn.length != 0) {
                if (txn.length < 64) throw new IllegalArgumentException("End of input");
                signature = Bytes.sub(txn, 0, 64);
                txn = Bytes.sub(txn, 64);
                assert txn.length == 0;
            }
            Dict fields = new Dict();
            fields.put("version", version);
            if (publickey != null) fields.put("publickey", publickey);
            if (asset != null) fields.put("asset", asset);
            if (fee_asset != null) fields.put("fee_asset", fee_asset);
            fields.put("timestamp", timestamp);
            fields.put("amount", amount);
            fields.put("fee", fee);
            fields.put("recipient", recipient);
            if (attachment.length() > 0) fields.put("attachment", attachment);
            if (signature != null) fields.put("signature", signature);
            return fields;
        }
        if (fmt.equals("cbor")) {
            Dict fields = new Dict();
            Object[] data = (Object[]) Cbor.loads(txn);
            if (data.length == 2) {
                Object[] witnesses = (Object[]) data[1];
                data = (Object[]) data[0];
                Dict[] wits = new Dict[witnesses.length];
                for (int i = 0; i < witnesses.length; i++) {
                    Object[] witness = (Object[]) witnesses[i];
                    if (witness.length != 2) throw new IllegalArgumentException("Invalid input");
                    BigInteger typ = (BigInteger) witness[0];
                    Cbor.Tag obj = (Cbor.Tag) witness[1];
                    if (typ.compareTo(BigInteger.ZERO) != 0) throw new IllegalArgumentException("Unknown type");
                    if (obj.tag.compareTo(BigInteger.valueOf(24)) != 0)
                        throw new IllegalArgumentException("Unknown tag");
                    Object[] r = (Object[]) Cbor.loads((byte[]) obj.value);
                    if (r.length != 2) throw new IllegalArgumentException("Invalid input");
                    byte[] b = (byte[]) r[0];
                    byte[] signature = (byte[]) r[1];
                    Dict wit = new Dict();
                    wit.put("publickey", Binint.b2h(Bytes.sub(b, 0, 32)));
                    wit.put("chaincode", Binint.b2h(Bytes.sub(b, 32)));
                    wit.put("signature", signature);
                    wits[i] = wit;
                }
                fields.put("witnesses", wits);
            }
            List<Object> inputs = (List<Object>) data[0];
            Dict[] ins = new Dict[inputs.size()];
            for (int i = 0; i < inputs.size(); i++) {
                Object[] input = (Object[]) inputs.get(i);
                if (input.length != 2) throw new IllegalArgumentException("Invalid input");
                BigInteger typ = (BigInteger) input[0];
                Cbor.Tag obj = (Cbor.Tag) input[1];
                if (typ.compareTo(BigInteger.ZERO) != 0) throw new IllegalArgumentException("Unknown type");
                if (obj.tag.compareTo(BigInteger.valueOf(24)) != 0) throw new IllegalArgumentException("Unknown tag");
                Object[] r = (Object[]) Cbor.loads((byte[]) obj.value);
                byte[] b = (byte[]) r[0];
                BigInteger index = (BigInteger) r[1];
                Dict in = new Dict();
                in.put("txnid", Binint.b2h(b));
                in.put("index", index);
                ins[i] = in;
            }
            fields.put("inputs", ins);
            List<Object> outputs = (List<Object>) data[1];
            Dict[] outs = new Dict[outputs.size()];
            for (int i = 0; i < outputs.size(); i++) {
                Object[] output = (Object[]) outputs.get(i);
                if (output.length != 2) throw new IllegalArgumentException("Invalid input");
                Object[] struct = (Object[]) output[0];
                BigInteger amount = (BigInteger) output[1];
                if (struct.length != 2) throw new IllegalArgumentException("Invalid input");
                Cbor.Tag obj = (Cbor.Tag) struct[0];
                BigInteger checksum = (BigInteger) struct[1];
                if (obj.tag.compareTo(BigInteger.valueOf(24)) != 0) throw new IllegalArgumentException("Unknown tag");
                BigInteger expected_checksum = Binint.b2n(Crc32.crc32xmodem((byte[]) obj.value));
                if (checksum.compareTo(expected_checksum) != 0)
                    throw new IllegalArgumentException("Inconsistent checksum");
                String address = Base58.encode(Cbor.dumps(struct));
                Dict out = new Dict();
                out.put("address", address);
                out.put("amount", amount);
                outs[i] = out;
            }
            fields.put("outputs", outs);
            Map<Object, Object> attrs = (Map<Object, Object>) data[2];
            if (attrs.size() > 0) throw new IllegalArgumentException("Unsupported attributes");
            return fields;
        }
        if (fmt.equals("protobuf")) {
            Map<Integer, Object> meta_1 = new HashMap<>();
            Map<Integer, Object> meta_2 = new HashMap<>();
            meta_2.put(2, meta_1);
            Map<Integer, Object> meta_3 = new HashMap<>();
            meta_3.put(2, meta_2);
            Map<Integer, Object> meta = new HashMap<>();
            meta.put(11, meta_3);
            Dict fields = new Dict();
            Map<Integer, Object> data = (Map<Integer, Object>) Protobuf.loads(txn, meta);
            if (!data.containsKey(11)) {
                fields.put("signature", data.get(2));
                data = (Map<Integer, Object>) Protobuf.loads((byte[]) data.get(1), meta);
            }
            fields.put("ref_block_bytes", data.get(1));
            fields.put("ref_block_hash", data.get(4));
            fields.put("expiration", data.get(8));
            Map<Integer, Object> contract = (Map<Integer, Object>) data.get(11);
            BigInteger contract_type = (BigInteger) contract.get(1);
            if (contract_type.compareTo(BigInteger.ONE) != 0)
                throw new IllegalArgumentException("Unsupported contract type");
            Map<Integer, Object> message = (Map<Integer, Object>) contract.get(2);
            byte[] message_type = (byte[]) message.get(1);
            if (!Bytes.equ(message_type, "type.googleapis.com/protocol.TransferContract".getBytes()))
                throw new IllegalArgumentException("Unsupported message type");
            Map<Integer, Object> message_params = (Map<Integer, Object>) message.get(2);
            String[] kinds = Coins.attr("address.kinds", new String[]{"address"}, coin, testnet);
            byte[] owner_address = (byte[]) message_params.get(1);
            for (String kind : kinds) {
                byte[] prefix = Coins.attr(kind + ".base58.prefix", coin, testnet);
                if (!Bytes.equ(Bytes.sub(owner_address, 0, prefix.length), prefix)) continue;
                fields.put("owner_address", Wallet.address_encode(Binint.b2n(Bytes.sub(owner_address, prefix.length)), kind, coin, testnet));
            }
            if (!fields.has("owner_address")) throw new IllegalArgumentException("Unsupported owner address");
            byte[] to_address = (byte[]) message_params.get(2);
            for (String kind : kinds) {
                byte[] prefix = Coins.attr(kind + ".base58.prefix", coin, testnet);
                if (!Bytes.equ(Bytes.sub(to_address, 0, prefix.length), prefix)) continue;
                fields.put("to_address", Wallet.address_encode(Binint.b2n(Bytes.sub(to_address, prefix.length)), kind, coin, testnet));
            }
            if (!fields.has("to_address")) throw new IllegalArgumentException("Unsupported to address");
            fields.put("amount", message_params.get(3));
            return fields;
        }
        throw new IllegalStateException("Unknown format");
    }

    public static String txnid(byte[] txn, String coin, boolean testnet) {
        String txnfmt = Coins.attr("transaction.format", coin, testnet);
        if (txnfmt.equals("neoinout")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("scripts")) fields.del("scripts");
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("dcrinout")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            BigInteger version = fields.get("version");
            version = version.or(BigInteger.ONE.shiftLeft(16));
            fields.put("version", version);
            fields.put("witnesses", null);
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("xdr")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("Signatures")) fields.del("Signatures");
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("raiblock")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            if (fields.has("work")) fields.del("work");
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("wavestx")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            txn = transaction_encode(fields, coin, testnet);
            txn = Bytes.sub(txn, 1);
        }
        if (txnfmt.equals("cbor")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("witnesses")) fields.del("witnesses");
            txn = transaction_encode(fields, coin, testnet);
        }
        if (txnfmt.equals("protobuf")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            txn = transaction_encode(fields, coin, testnet);
        }
        String fun = Coins.attr("transaction.hashing", coin, testnet);
        byte[] prefix = Coins.attr("transaction.hashing.prefix", new byte[]{}, coin, testnet);
        byte[] b;
        switch (fun) {
            case "hash256":
                b = Hashing.hash256(Bytes.concat(prefix, txn));
                break;
            case "keccak256":
                b = Hashing.keccak256(Bytes.concat(prefix, txn));
                break;
            case "sha256":
                b = Hashing.sha256(Bytes.concat(prefix, txn));
                break;
            case "sha512h":
                b = Hashing.sha512h(Bytes.concat(prefix, txn));
                break;
            case "blake1s":
                b = Hashing.blake1s(Bytes.concat(prefix, txn));
                break;
            case "blake2b256":
                b = Hashing.blake2b(Bytes.concat(prefix, txn), 32);
                break;
            default:
                throw new IllegalStateException("Unknown hashing function");
        }
        boolean reverse = Coins.attr("transaction.hashing.reverse", false, coin, testnet);
        if (reverse) r(b);
        int bits = Coins.attr("transaction.id.bits", 256, coin, testnet);
        b = Bytes.sub(b, b.length - bits / 8);
        String fmt = Coins.attr("transaction.id.format", "hex", coin, testnet);
        switch (fmt) {
            case "hex":
                return Binint.b2h(b);
            case "decimal":
                return Binint.b2n(b).toString();
            case "base58":
                return Base58.encode(b);
            default:
                throw new IllegalStateException("Unknown format");
        }
    }

    private static byte[] sighash_default(Dict fields, int i, byte[] inscript, BigInteger amount, int flag, String coin, boolean testnet) {
        Dict[] inputs = fields.get("inputs");
        inputs[i].put("script", inscript);
        byte[] txn = transaction_encode(fields, coin, testnet);
        inputs[i].put("script", new byte[]{});
        byte[] f = int32(BigInteger.valueOf(flag));
        return Bytes.concat(txn, f);
    }

    private static byte[] sighash_forkid(Dict fields, int i, byte[] inscript, BigInteger amount, int flag, String coin, boolean testnet) {
        if (amount == null) throw new IllegalArgumentException("Amount required");
        BigInteger version = fields.get("version");
        Dict[] inputs = fields.get("inputs");
        Dict[] outputs = fields.get("outputs");
        BigInteger locktime = fields.get("locktime");
        int t2_length = (32 + 4) * inputs.length;
        byte[] t2 = new byte[t2_length];
        int t2_offset = 0;
        for (Dict input : inputs) {
            byte[] txnid = Binint.h2b(input.get("txnid"));
            r(txnid);
            byte[] b = int32(input.get("index"));
            System.arraycopy(txnid, 0, t2, t2_offset, txnid.length);
            t2_offset += txnid.length;
            System.arraycopy(b, 0, t2, t2_offset, b.length);
            t2_offset += b.length;
        }
        int t3_length = 4 * inputs.length;
        byte[] t3 = new byte[t3_length];
        int t3_offset = 0;
        for (Dict input : inputs) {
            byte[] b = int32(input.get("sequence"));
            System.arraycopy(b, 0, t3, t3_offset, b.length);
            t3_offset += b.length;
        }
        int t10_length = 0;
        for (Dict output : outputs) {
            byte[] outscript = output.get("script");
            t10_length += 8 + varint(BigInteger.valueOf(outscript.length)).length + outscript.length;
        }
        byte[] t10 = new byte[t10_length];
        int t10_offset = 0;
        for (Dict output : outputs) {
            byte[] b = int64(output.get("amount"));
            byte[] outscript = output.get("script");
            byte[] l = varint(BigInteger.valueOf(outscript.length));
            System.arraycopy(b, 0, t10, t10_offset, b.length);
            t10_offset += b.length;
            System.arraycopy(l, 0, t10, t10_offset, l.length);
            t10_offset += l.length;
            System.arraycopy(outscript, 0, t10, t10_offset, outscript.length);
            t10_offset += outscript.length;
        }
        Dict subfields = inputs[i];
        byte[] txnid = Binint.h2b(subfields.get("txnid"));
        r(txnid);
        BigInteger index = subfields.get("index");
        BigInteger sequence = subfields.get("sequence");
        byte[] b1 = int32(version);
        byte[] b2 = Hashing.hash256(t2);
        byte[] b3 = Hashing.hash256(t3);
        byte[] b4 = txnid;
        byte[] b5 = int32(index);
        byte[] b6 = varint(BigInteger.valueOf(inscript.length));
        byte[] b7 = inscript;
        byte[] b8 = int64(amount);
        byte[] b9 = int32(sequence);
        byte[] b10 = Hashing.hash256(t10);
        byte[] b11 = int32(locktime);
        byte[] b12 = int32(BigInteger.valueOf(flag));
        return Bytes.concat(Bytes.concat(b1, b2, b3, b4, b5, b6), Bytes.concat(b7, b8, b9, b10, b11, b12));
    }

    private static byte[] sighash_sapling(Dict fields, int i, byte[] inscript, BigInteger amount, int flag, String coin, boolean testnet) {
        if (amount == null) throw new IllegalArgumentException("Amount required");
        BigInteger version = fields.get("version");
        BigInteger groupid = fields.get("groupid");
        Dict[] inputs = fields.get("inputs");
        Dict[] outputs = fields.get("outputs");
        BigInteger locktime = fields.get("locktime");
        BigInteger expiryheight = fields.get("expiryheight");
        int t3_length = (32 + 4) * inputs.length;
        byte[] t3 = new byte[t3_length];
        int t3_offset = 0;
        for (Dict input : inputs) {
            byte[] txnid = Binint.h2b(input.get("txnid"));
            r(txnid);
            byte[] b = int32(input.get("index"));
            System.arraycopy(txnid, 0, t3, t3_offset, txnid.length);
            t3_offset += txnid.length;
            System.arraycopy(b, 0, t3, t3_offset, b.length);
            t3_offset += b.length;
        }
        int t4_length = 4 * inputs.length;
        byte[] t4 = new byte[t4_length];
        int t4_offset = 0;
        for (Dict input : inputs) {
            byte[] b = int32(input.get("sequence"));
            System.arraycopy(b, 0, t4, t4_offset, b.length);
            t4_offset += b.length;
        }
        int t5_length = 0;
        for (Dict output : outputs) {
            byte[] outscript = output.get("script");
            t5_length += 8 + varint(BigInteger.valueOf(outscript.length)).length + outscript.length;
        }
        byte[] t5 = new byte[t5_length];
        int t5_offset = 0;
        for (Dict output : outputs) {
            byte[] b = int64(output.get("amount"));
            byte[] outscript = output.get("script");
            byte[] l = varint(BigInteger.valueOf(outscript.length));
            System.arraycopy(b, 0, t5, t5_offset, b.length);
            t5_offset += b.length;
            System.arraycopy(l, 0, t5, t5_offset, l.length);
            t5_offset += l.length;
            System.arraycopy(outscript, 0, t5, t5_offset, outscript.length);
            t5_offset += outscript.length;
        }
        Dict subfields = inputs[i];
        byte[] txnid = Binint.h2b(subfields.get("txnid"));
        r(txnid);
        BigInteger index = subfields.get("index");
        BigInteger sequence = subfields.get("sequence");
        byte[] b1 = int32(version);
        byte[] b2 = int32(groupid);
        byte[] b3 = Hashing.blake2b(t3, "ZcashPrevoutHash".getBytes(), 32);
        byte[] b4 = Hashing.blake2b(t4, "ZcashSequencHash".getBytes(), 32);
        byte[] b5 = Hashing.blake2b(t5, "ZcashOutputsHash".getBytes(), 32);
        byte[] b6 = new byte[32];
        byte[] b7 = new byte[32];
        byte[] b8 = new byte[32];
        byte[] b9 = int32(locktime);
        byte[] b10 = int32(expiryheight);
        byte[] b11 = int64(BigInteger.ZERO);
        byte[] b12 = int32(BigInteger.valueOf(flag));
        byte[] b13 = txnid;
        byte[] b14 = int32(index);
        byte[] b15 = varint(BigInteger.valueOf(inscript.length));
        byte[] b16 = inscript;
        byte[] b17 = int64(amount);
        byte[] b18 = int32(sequence);
        return Bytes.concat(Bytes.concat(b1, b2, b3, b4, b5, b6), Bytes.concat(b7, b8, b9, b10, b11, b12), Bytes.concat(b13, b14, b15, b16, b17, b18));
    }

    private static byte[] dcrsighash_default(Dict fields, int i, byte[] inscript, BigInteger amount, int flag, String coin, boolean testnet) {
        BigInteger version = fields.get("version");
        fields.put("version", version.or(BigInteger.ONE.shiftLeft(16)));
        byte[] txn = transaction_encode(fields, coin, testnet);
        fields.put("version", version);
        Dict[] inputs = fields.get("inputs");
        byte[] b = int32(version.or(BigInteger.valueOf(3).shiftLeft(16)));
        b = Bytes.concat(b, varint(BigInteger.valueOf(inputs.length)));
        for (int index = 0; index < inputs.length; index++) {
            byte[] s = index == i ? inscript : new byte[]{};
            b = Bytes.concat(b, varint(BigInteger.valueOf(s.length)), s);
        }
        byte[] b1 = int32(BigInteger.valueOf(flag));
        byte[] b2 = Hashing.blake1s(txn);
        byte[] b3 = Hashing.blake1s(b);
        return Bytes.concat(b1, b2, b3);
    }

    public static byte[] transaction_sign(byte[] txn, Object params, String coin, boolean testnet) {
        String fmt = Coins.attr("transaction.format", coin, testnet);
        if (fmt.equals("inout")) {
            int sighashflag = SIGHASH_ALL;
            String method = Coins.attr("sighash.method", coin, testnet);
            sighashfun sighashfunc;
            if (method.equals("default")) sighashfunc = Transaction::sighash_default;
            else if (method.equals("sapling")) sighashfunc = Transaction::sighash_sapling;
            else if (method.equals("forkid")) {
                sighashfunc = Transaction::sighash_forkid;
                int forkid = Coins.attr("sighash.forkid", coin, testnet);
                sighashflag |= (forkid << 8) | SIGHASH_FORKID;
            } else {
                throw new IllegalStateException("Unknown method");
            }
            Dict fields = transaction_decode(txn, coin, testnet);
            Dict[] inputs = fields.get("inputs");
            if (!(params instanceof Object[])) {
                Object[] t = new Object[inputs.length];
                for (int i = 0; i < t.length; i++) t[i] = params;
                params = t;
            }
            Object[] _params = (Object[]) params;
            for (Dict subfields : inputs) {
                subfields.put("script", new byte[]{});
            }
            byte[][] inscripts = new byte[inputs.length][];
            for (int i = 0; i < inputs.length; i++) {
                Object param = _params[i];
                if (!(param instanceof Dict)) {
                    String privatekey = null;
                    BigInteger amount = null;
                    if (param instanceof String) {
                        privatekey = (String) param;
                    }
                    if (param instanceof Object[]) {
                        Object[] tuple = (Object[]) param;
                        privatekey = (String) tuple[0];
                        amount = (BigInteger) tuple[1];
                    }
                    String publickey = Wallet.publickey_from_privatekey(privatekey, coin, testnet);
                    String address = Wallet.address_from_publickey(publickey, coin, testnet);
                    Dict _dict = new Dict();
                    _dict.put("privatekeys", new String[]{privatekey});
                    _dict.put("script", Script.scriptpubkey(address, null, coin, testnet));
                    _dict.put("scriptsigfun", (scriptsigfun) (signatures -> Script.scriptsig(signatures[0], publickey)));
                    _dict.put("amount", amount);
                    param = _dict;
                }
                Dict _dict = (Dict) param;
                String[] privatekeys = _dict.get("privatekeys");
                byte[] inscript = _dict.get("script");
                scriptsigfun scriptsigfun = _dict.get("scriptsigfun");
                BigInteger amount = _dict.get("amount", null);
                byte[] sighashdata = sighashfunc.f(fields, i, inscript, amount, sighashflag, coin, testnet);
                byte[][] signatures = new byte[privatekeys.length][];
                for (int j = 0; j < privatekeys.length; j++) {
                    String privatekey = privatekeys[j];
                    byte[] signature = Signing.signature_create(privatekey, sighashdata, null, coin, testnet);
                    byte[] f = int8(BigInteger.valueOf(sighashflag & 0xff));
                    signatures[j] = Bytes.concat(signature, f);
                }
                inscript = scriptsigfun.f(signatures);
                inscripts[i] = inscript;
            }
            for (int i = 0; i < inputs.length; i++) {
                Dict subfields = inputs[i];
                subfields.put("script", inscripts[i]);
            }
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("dcrinout")) {
            int sighashflag = SIGHASH_ALL;
            String method = Coins.attr("sighash.method", coin, testnet);
            sighashfun sighashfunc;
            if (method.equals("default")) sighashfunc = Transaction::dcrsighash_default;
            else {
                throw new IllegalStateException("Unknown method");
            }
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("witnesses")) fields.del("witnesses");
            Dict[] inputs = fields.get("inputs");
            if (!(params instanceof Object[])) {
                Object[] t = new Object[inputs.length];
                for (int i = 0; i < t.length; i++) t[i] = params;
                params = t;
            }
            Object[] _params = (Object[]) params;
            Dict[] witnesses = new Dict[inputs.length];
            for (int i = 0; i < inputs.length; i++) {
                Object param = _params[i];
                if (!(param instanceof Dict)) {
                    String privatekey = null;
                    BigInteger amount = BigInteger.ZERO;
                    if (param instanceof String) {
                        privatekey = (String) param;
                    }
                    if (param instanceof Object[]) {
                        Object[] tuple = (Object[]) param;
                        privatekey = (String) tuple[0];
                        amount = (BigInteger) tuple[1];
                    }
                    String publickey = Wallet.publickey_from_privatekey(privatekey, coin, testnet);
                    String address = Wallet.address_from_publickey(publickey, coin, testnet);
                    Pair<BigInteger[], Boolean> t1 = Wallet.publickey_decode(publickey, coin, testnet);
                    BigInteger[] P = t1.l;
                    boolean compressed = t1.r;
                    Pair<BigInteger, Boolean> t2 = Secp256k1.enc(P);
                    BigInteger p = t2.l;
                    boolean odd = t2.r;
                    byte[] prefix = odd ? new byte[]{(byte) 0x03} : new byte[]{(byte) 0x02};
                    byte[] b = Bytes.concat(prefix, Binint.n2b(p, 32));
                    String publickey_sec2 = Binint.b2h(b);
                    Dict _dict = new Dict();
                    _dict.put("privatekeys", new String[]{privatekey});
                    _dict.put("script", Script.scriptpubkey(address, null, coin, testnet));
                    _dict.put("scriptsigfun", (scriptsigfun) (signatures -> Script.scriptsig(signatures[0], publickey_sec2)));
                    _dict.put("amount", amount);
                    param = _dict;
                }
                Dict _dict = (Dict) param;
                String[] privatekeys = _dict.get("privatekeys");
                byte[] inscript = _dict.get("script");
                scriptsigfun scriptsigfun = _dict.get("scriptsigfun");
                BigInteger amount = _dict.get("amount", BigInteger.ZERO);
                byte[] sighashdata = sighashfunc.f(fields, i, inscript, amount, sighashflag, coin, testnet);
                byte[][] signatures = new byte[privatekeys.length][];
                for (int j = 0; j < privatekeys.length; j++) {
                    String privatekey = privatekeys[j];
                    byte[] signature = Signing.signature_create(privatekey, sighashdata, null, coin, testnet);
                    byte[] f = int8(BigInteger.valueOf(sighashflag & 0xff));
                    signatures[j] = Bytes.concat(signature, f);
                }
                inscript = scriptsigfun.f(signatures);
                Dict witness = new Dict();
                if (_dict.has("amount")) witness.put("amount", _dict.get("amount"));
                if (_dict.has("blockheight")) witness.put("blockheight", _dict.get("blockheight"));
                if (_dict.has("blockindex")) witness.put("blockindex", _dict.get("blockindex"));
                witness.put("script", inscript);
                witnesses[i] = witness;
            }
            fields.put("witnesses", witnesses);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("neoinout")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            Dict[] inputs = fields.get("inputs");
            if (fields.has("scripts")) fields.del("scripts");
            txn = transaction_encode(fields, coin, testnet);
            if (!(params instanceof Object[])) {
                Object[] t = new Object[inputs.length];
                for (int i = 0; i < t.length; i++) t[i] = params;
                params = t;
            }
            Object[] _params = (Object[]) params;
            List<String> hashset = new ArrayList<>();
            Map<String, Dict> scriptmap = new HashMap<>();
            for (Object param : _params) {
                String privatekey = null;
                BigInteger amount = null;
                if (param instanceof String) {
                    privatekey = (String) param;
                }
                if (param instanceof Object[]) {
                    Object[] tuple = (Object[]) param;
                    privatekey = (String) tuple[0];
                    amount = (BigInteger) tuple[1];
                }
                String publickey = Wallet.publickey_from_privatekey(privatekey, coin, testnet);
                String address = Wallet.address_from_publickey(publickey, coin, testnet);
                Pair<BigInteger, String> t = Wallet.address_decode(address, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                String hash160 = Binint.b2h(Bytes.rev(Binint.n2b(h, 20)));
                if (hashset.contains(hash160)) continue;
                byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
                byte[] invocation_script = Script.OP_PUSHDATA(signature);
                byte[] verification_script = Bytes.concat(Script.OP_PUSHDATA(Binint.h2b(publickey)), Script.OP_CHECKSIG);
                hashset.add(hash160);
                Dict map = new Dict();
                map.put("invocation", invocation_script);
                map.put("verification", verification_script);
                scriptmap.put(hash160, map);
            }
            Collections.sort(hashset);
            List<Dict> scripts = new ArrayList<>();
            for (String hash160 : hashset) {
                scripts.add(scriptmap.get(hash160));
            }
            fields.put("scripts", scripts.toArray(new Dict[]{}));
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("rlp")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("v")) fields.del("v");
            if (fields.has("r")) fields.del("r");
            if (fields.has("s")) fields.del("s");
            // chain id protects against replay attacks EIP 155
            int chain_id = Coins.attr("chain.id", -1, coin, testnet);
            if (chain_id != -1) {
                fields.put("v", Binint.n2b(BigInteger.valueOf(chain_id), 1));
                fields.put("r", new byte[0]);
                fields.put("s", new byte[0]);
            }
            String privatekey = (String) params;
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
            Object[] t = Signing.signature_decode(signature, coin, testnet);
            BigInteger r = (BigInteger) t[0];
            BigInteger s = (BigInteger) t[1];
            boolean odd = (boolean) t[2];
            int v = 27 + (odd ? 1 : 0);
            if (chain_id != -1) v += 8 + 2 * chain_id;
            fields.put("v", Binint.n2b(BigInteger.valueOf(v), 1));
            fields.put("r", Binint.n2b(r, 32));
            fields.put("s", Binint.n2b(s, 32));
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("serial")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("TxnSignature")) fields.del("TxnSignature");
            String privatekey = (String) params;
            fields.put("Flags", BigInteger.valueOf(0x80000000L)); // tfFullyCanonicalSig
            fields.put("SigningPubKey", Wallet.publickey_from_privatekey(privatekey, coin, testnet));
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("TxnSignature", Binint.b2h(signature));
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("xdr")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            String account = fields.get("Account");
            Pair<BigInteger, String> t = Wallet.address_decode(account, coin, testnet);
            BigInteger p = t.l;
            String kind = t.r;
            byte[] b_account = Binint.n2b(p, 32);
            if (fields.has("Signatures")) fields.del("Signatures");
            String privatekey = (String) params;
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
            byte[] hint = Bytes.sub(b_account, -4);
            Dict sigobject = new Dict();
            sigobject.put("Hint", hint);
            sigobject.put("Signature", signature);
            fields.put("Signatures", new Dict[]{sigobject});
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("raiblock")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            byte[] work = fields.get("work", null);
            if (fields.has("signature")) fields.del("signature");
            if (fields.has("work")) fields.del("work");
            String privatekey = (String) params;
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("signature", signature);
            if (work == null) {
                long threshold = Coins.attr("transaction.pow.threshold", coin, testnet);
                BigInteger _threshold = BigInteger.valueOf(threshold);
                if (_threshold.compareTo(BigInteger.ZERO) < 0) {
                    _threshold = BigInteger.ONE.shiftLeft(64).add(_threshold);
                }
                byte[] previous = Binint.h2b((String) fields.get("previous"));
                if (Binint.b2n(previous).equals(BigInteger.ZERO)) {
                    String account = (String) fields.get("account");
                    Pair<BigInteger, String> t = Wallet.address_decode(account, coin, testnet);
                    BigInteger h = t.l;
                    String kind = t.r;
                    previous = Binint.n2b(h, 32);
                }
                BigInteger i = BigInteger.ZERO;
                while (true) {
                    work = Binint.n2b(i, 8);
                    byte[] b = Bytes.rev(Hashing.blake2b(Bytes.concat(Bytes.rev(work), previous), 8));
                    if (Binint.b2n(b).compareTo(_threshold) > 0) break;
                    i = i.add(BigInteger.ONE);
                }
            }
            fields.put("work", work);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("liskdatablock")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            String privatekey = (String) params;
            String publickey = Wallet.publickey_from_privatekey(privatekey, coin, testnet);
            fields.put("publickey", publickey);
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("signature", signature);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("wavestx")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            String privatekey = (String) params;
            String publickey = Wallet.publickey_from_privatekey(privatekey, coin, testnet);
            fields.put("publickey", publickey);
            txn = transaction_encode(fields, coin, testnet);
            txn = Bytes.sub(txn, 1);
            byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("signature", signature);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("cbor")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("witnesses")) fields.del("witnesses");
            txn = transaction_encode(fields, coin, testnet);
            Dict[] inputs = fields.get("inputs");
            if (!(params instanceof Object[])) {
                Object[] t = new Object[inputs.length];
                for (int i = 0; i < t.length; i++) t[i] = params;
                params = t;
            }
            Object[] _params = (Object[]) params;
            Dict[] witnesses = new Dict[inputs.length];
            for (int i = 0; i < inputs.length; i++) {
                Object param = _params[i];
                String privatekey = null;
                if (param instanceof String) {
                    privatekey = (String) param;
                }
                if (param instanceof Object[]) {
                    Object[] tuple = (Object[]) param;
                    privatekey = (String) tuple[0];
                }
                String publickey = Wallet.publickey_from_privatekey(privatekey, coin, testnet);
                byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
                Dict witness = new Dict();
                witness.put("publickey", publickey);
                witness.put("chaincode", Binint.b2h(new byte[32]));
                witness.put("signature", signature);
                witnesses[i] = witness;
            }
            fields.put("witnesses", witnesses);
            return transaction_encode(fields, coin, testnet);
        }
        if (fmt.equals("protobuf")) {
            Dict fields = transaction_decode(txn, coin, testnet);
            if (fields.has("signature")) fields.del("signature");
            String privatekey = (String) params;
            txn = transaction_encode(fields, coin, testnet);
            byte[] signature = Signing.signature_create(privatekey, txn, null, coin, testnet);
            fields.put("signature", signature);
            return transaction_encode(fields, coin, testnet);
        }
        throw new IllegalStateException("Unknown format");
    }

    public interface sighashfun {
        byte[] f(Dict fields, int i, byte[] inscript, BigInteger amount, int sighashflag, String coin, boolean testnet);
    }

    public interface scriptsigfun {
        byte[] f(byte[][] signatures);
    }

}
