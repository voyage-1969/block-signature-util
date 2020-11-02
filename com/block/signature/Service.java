package com.block.signature;

import com.block.signature.calculate.Binint;
import com.block.signature.calculate.Bytes;
import com.block.signature.calculate.Hashing;
import com.block.signature.struct.Dict;
import com.block.signature.struct.Pair;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Service {

    public interface callback {
        BigInteger get_fee(String coin, boolean testnet);

        BigInteger get_balance(String address, String coin, boolean testnet);

        Dict[] get_utxos(String address, String coin, boolean testnet);

        BigInteger get_txn_count(String address, String coin, boolean testnet);

        String broadcast_txn(byte[] txn, String coin, boolean testnet);

        Object custom_call(String name, Object arg, String coin, boolean testnet);
    }

    public static BigInteger estimate_fee(Object _source_addresses, BigInteger amount, String coin, boolean testnet, callback cb) {
        if (!(_source_addresses instanceof String[])) _source_addresses = new String[]{ (String) _source_addresses };
        String[] source_addresses = (String[]) _source_addresses;
        BigInteger fee = cb.get_fee(coin, testnet);
        String fmt = Coins.attr("transaction.format", coin, testnet);
        if (fmt.equals("inout")) {
            List<Dict> list = new ArrayList<>();
            for (String source_address : source_addresses) {
                list.addAll(Arrays.asList(cb.get_utxos(source_address, coin, testnet)));
            }
            Dict[] utxos = list.toArray(new Dict[]{});
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger amount1 = o1.get("amount");
                BigInteger amount2 = o2.get("amount");
                return amount2.compareTo(amount1);
            });
            BigInteger balance = BigInteger.ZERO;
            BigInteger estimatefee = BigInteger.ZERO;
            for (int i = 1; i <= utxos.length; i++) {
                int estimatesize = 4 + (1 + i * (32 + 4 + (1 + (1 + 72) + (1 + 33)) + 4)) + (1 + 2 * (8 + (1 + 25))) + 4;
                estimatefee = fee.multiply(BigInteger.valueOf(estimatesize)).shiftRight(10);
                balance = balance.add((BigInteger) utxos[i - 1].get("amount"));
                if (balance.compareTo(amount.add(estimatefee)) >= 0) break;
            }
            return estimatefee;
        }
        if (fmt.equals("dcrinout")) {
            List<Dict> list = new ArrayList<>();
            for (String source_address : source_addresses) {
                list.addAll(Arrays.asList(cb.get_utxos(source_address, coin, testnet)));
            }
            Dict[] utxos = list.toArray(new Dict[]{});
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger amount1 = o1.get("amount");
                BigInteger amount2 = o2.get("amount");
                return amount2.compareTo(amount1);
            });
            BigInteger balance = BigInteger.ZERO;
            BigInteger estimatefee = BigInteger.ZERO;
            for (int i = 1; i <= utxos.length; i++) {
                int estimatesize = 4 + (1 + i * (32 + 4 + 1 + 4)) + (1 + 2 * (8 + 2 + (1 + 25))) + 4 + 4 + (1 + i * (8 + 4 + 4 + (1 + (1 + 73) + (1 + 33))));
                estimatefee = fee.multiply(BigInteger.valueOf(estimatesize)).shiftRight(10);
                balance = balance.add((BigInteger) utxos[i - 1].get("amount"));
                if (balance.compareTo(amount.add(estimatefee)) >= 0) break;
            }
            return estimatefee;
        }
        if (fmt.equals("neoinout")) {
            return BigInteger.ZERO;
        }
        if (fmt.equals("rlp")) {
            int gas = Coins.attr("transfer.gaslimit", coin, testnet);
            BigInteger gaslimit = BigInteger.valueOf(gas);
            BigInteger gasprice = fee;
            return gaslimit.multiply(gasprice);
        }
        if (fmt.equals("serial")) {
            return fee;
        }
        if (fmt.equals("xdr")) {
            return fee;
        }
        if (fmt.equals("raiblock")) {
            return BigInteger.ZERO;
        }
        if (fmt.equals("liskdatablock")) {
            return fee;
        }
        if (fmt.equals("wavestx")) {
            return fee;
        }
        if (fmt.equals("cbor")) {
            List<Dict> list = new ArrayList<>();
            for (String source_address : source_addresses) {
                list.addAll(Arrays.asList(cb.get_utxos(source_address, coin, testnet)));
            }
            Dict[] utxos = list.toArray(new Dict[]{});
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger amount1 = o1.get("amount");
                BigInteger amount2 = o2.get("amount");
                return amount2.compareTo(amount1);
            });
            BigInteger balance = BigInteger.ZERO;
            BigInteger estimatefee = BigInteger.ZERO;
            for (int i = 1; i <= utxos.length; i++) {
                int estimatesize = 1 + (1 + (1 + i * (1 + 1 + 4 + 1 + (2 + 32) + 5) + 1) + (1 + 2 * (1 + 1 + 4 + 1 + (2 + 28 + ((1 + (4 + 30)) / 2) + (testnet ? 5 : 0) + 1) + 5 + 9) + 1) + 1) + (1 + i * (1 + 1 + 4 + 1 + 2 + 64 + 2 + 64));
                BigDecimal factor = new BigDecimal(43.946).multiply(new BigDecimal(estimatesize));
                estimatefee = new BigDecimal(155381).add(factor).setScale(0, BigDecimal.ROUND_CEILING).toBigIntegerExact();
                balance = balance.add((BigInteger) utxos[i-1].get("amount"));
                if (balance.compareTo(amount.add(estimatefee)) >= 0) break;
            }
            return estimatefee;
        }
        if (fmt.equals("protobuf")) {
            return BigInteger.ZERO;
        }
        throw new IllegalArgumentException("Unknown format");
    }

    public static Pair<byte[][], context> create_rawtxn(Object _source_addresses, String address, BigInteger amount, BigInteger fee, String change_address, String coin, boolean testnet, callback cb) {
        if (!(_source_addresses instanceof String[])) _source_addresses = new String[]{(String) _source_addresses};
        String[] source_addresses = (String[]) _source_addresses;
        if (amount.compareTo(BigInteger.ZERO) <= 0) throw new IllegalArgumentException("Invalid amount");
        if (fee.compareTo(BigInteger.ZERO) < 0) throw new IllegalArgumentException("Invalid fee");
        if (change_address == null) change_address = source_addresses[0];
        String fmt = Coins.attr("transaction.format", coin, testnet);
        if (fmt.equals("inout")) {
            List<Dict> list = new ArrayList<>();
            for (String source_address : source_addresses) {
                list.addAll(Arrays.asList(cb.get_utxos(source_address, coin, testnet)));
            }
            Dict[] utxos = list.toArray(new Dict[]{});
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger amount1 = o1.get("amount");
                BigInteger amount2 = o2.get("amount");
                return amount2.compareTo(amount1);
            });
            BigInteger balance = BigInteger.ZERO;
            for (int i = 1; i <= utxos.length; i++) {
                balance = balance.add(utxos[i - 1].get("amount"));
                if (balance.compareTo(amount.add(fee)) >= 0) {
                    Dict[] t = new Dict[i];
                    System.arraycopy(utxos, 0, t, 0, t.length);
                    utxos = t;
                    break;
                }
            }
            Dict[] _utxos = utxos;
            context f = (lookup) -> {
                Object[] params = new Object[_utxos.length];
                for (int i = 0; i < _utxos.length; i++) {
                    Dict utxo = _utxos[i];
                    params[i] = new Object[]{lookup.call(utxo.get("address")), utxo.get("amount")};
                }
                return params;
            };
            Dict[] inputs = new Dict[utxos.length];
            for (int i = 0; i < utxos.length; i++) {
                Dict utxo = utxos[i];
                Dict input = new Dict();
                input.put("txnid", utxo.get("txnid"));
                input.put("index", utxo.get("index"));
                inputs[i] = input;
            }
            BigInteger change = balance.subtract(amount.add(fee));
            if (change.compareTo(BigInteger.ZERO) < 0) throw new IllegalArgumentException("Insufficient balance");
            boolean has_change = change.compareTo(BigInteger.ZERO) > 0;
            Dict[] outputs = new Dict[has_change ? 2 : 1];
            Dict output = new Dict();
            output.put("amount", amount);
            output.put("address", address);
            outputs[0] = output;
            if (has_change) {
                output = new Dict();
                output.put("amount", change);
                output.put("address", change_address);
                outputs[1] = output;
            }
            Dict fields = new Dict();
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        if (fmt.equals("dcrinout")) {
            List<Dict> list = new ArrayList<>();
            for (String source_address : source_addresses) {
                list.addAll(Arrays.asList(cb.get_utxos(source_address, coin, testnet)));
            }
            Dict[] utxos = list.toArray(new Dict[]{});
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger amount1 = o1.get("amount");
                BigInteger amount2 = o2.get("amount");
                return amount2.compareTo(amount1);
            });
            BigInteger balance = BigInteger.ZERO;
            for (int i = 1; i <= utxos.length; i++) {
                balance = balance.add(utxos[i - 1].get("amount"));
                if (balance.compareTo(amount.add(fee)) >= 0) {
                    Dict[] t = new Dict[i];
                    System.arraycopy(utxos, 0, t, 0, t.length);
                    utxos = t;
                    break;
                }
            }
            Dict[] _utxos = utxos;
            context f = (lookup) -> {
                Object[] params = new Object[_utxos.length];
                for (int i = 0; i < _utxos.length; i++) {
                    Dict utxo = _utxos[i];
                    params[i] = new Object[]{lookup.call(utxo.get("address")), utxo.get("amount")};
                }
                return params;
            };
            Dict[] inputs = new Dict[utxos.length];
            for (int i = 0; i < utxos.length; i++) {
                Dict utxo = utxos[i];
                Dict input = new Dict();
                input.put("txnid", utxo.get("txnid"));
                input.put("index", utxo.get("index"));
                inputs[i] = input;
            }
            BigInteger change = balance.subtract(amount.add(fee));
            if (change.compareTo(BigInteger.ZERO) < 0) throw new IllegalArgumentException("Insufficient balance");
            boolean has_change = change.compareTo(BigInteger.ZERO) > 0;
            Dict[] outputs = new Dict[has_change ? 2 : 1];
            Dict output = new Dict();
            output.put("amount", amount);
            output.put("address", address);
            outputs[0] = output;
            if (has_change) {
                output = new Dict();
                output.put("amount", change);
                output.put("address", change_address);
                outputs[1] = output;
            }
            Dict fields = new Dict();
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        if (fmt.equals("neoinout")) {
            String asset = Coins.attr("asset", coin, testnet);
            int decimals = Coins.attr("decimals", coin, testnet);
            List<Dict> list = new ArrayList<>();
            for (String source_address : source_addresses) {
                list.addAll(Arrays.asList(cb.get_utxos(source_address, coin, testnet)));
            }
            Dict[] utxos = list.toArray(new Dict[]{});
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger amount1 = o1.get("amount");
                BigInteger amount2 = o2.get("amount");
                return amount2.compareTo(amount1);
            });
            BigInteger balance = BigInteger.ZERO;
            for (int i = 1; i <= utxos.length; i++) {
                balance = balance.add(utxos[i - 1].get("amount"));
                if (balance.compareTo(amount.add(fee)) >= 0) {
                    Dict[] t = new Dict[i];
                    System.arraycopy(utxos, 0, t, 0, t.length);
                    utxos = t;
                    break;
                }
            }
            Dict[] _utxos = utxos;
            context f = (lookup) -> {
                Object[] params = new Object[_utxos.length];
                for (int i = 0; i < _utxos.length; i++) {
                    Dict utxo = _utxos[i];
                    params[i] = new Object[]{lookup.call(utxo.get("address")), utxo.get("amount")};
                }
                return params;
            };
            Dict[] inputs = new Dict[utxos.length];
            for (int i = 0; i < utxos.length; i++) {
                Dict utxo = utxos[i];
                Dict input = new Dict();
                input.put("txnid", utxo.get("txnid"));
                input.put("index", utxo.get("index"));
                inputs[i] = input;
            }
            BigInteger change = balance.subtract(amount.add(fee));
            if (change.compareTo(BigInteger.ZERO) < 0) throw new IllegalArgumentException("Insufficient balance");
            boolean has_change = change.compareTo(BigInteger.ZERO) > 0;
            BigInteger scale = BigInteger.TEN.pow(8 - decimals);
            Dict[] outputs = new Dict[has_change ? 2 : 1];
            Dict output = new Dict();
            output.put("asset", asset);
            output.put("amount", amount.multiply(scale));
            output.put("address", address);
            outputs[0] = output;
            if (has_change) {
                output = new Dict();
                output.put("asset", asset);
                output.put("amount", change.multiply(scale));
                output.put("address", change_address);
                outputs[1] = output;
            }
            Dict fields = new Dict();
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        if (fmt.equals("rlp")) {
            String source_address = source_addresses[0];
            context f = (lookup) -> lookup.call(source_address);
            int gas = Coins.attr("transfer.gaslimit", coin, testnet);
            BigInteger gaslimit = BigInteger.valueOf(gas);
            BigInteger gasprice = fee.divide(gaslimit);
            BigInteger nonce = cb.get_txn_count(source_address, coin, testnet);
            String contract = Coins.attr("contract.address", "", coin, testnet);
            if (contract.equals("")) {
                Dict fields = new Dict();
                fields.put("nonce", nonce);
                fields.put("gasprice", gasprice);
                fields.put("gaslimit", gaslimit);
                fields.put("to", address);
                fields.put("value", amount);
                byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
                return new Pair<>(new byte[][]{txn}, f);
            } else {
                Dict fields = new Dict();
                String funsig = "transfer(address,uint256)";
                byte[] b = Hashing.keccak256(funsig.getBytes());
                byte[] method = new byte[4];
                System.arraycopy(b, 0, method, 0, method.length);
                Pair<BigInteger, String> t = Wallet.address_decode(address, coin, testnet);
                BigInteger h = t.l;
                String kind = t.r;
                byte[] data = Bytes.concat(method, Binint.n2b(h, 32), Binint.n2b(amount, 32));
                fields.put("nonce", nonce);
                fields.put("gasprice", gasprice);
                fields.put("gaslimit", gaslimit);
                fields.put("to", contract);
                fields.put("data", data);
                byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
                return new Pair<>(new byte[][]{txn}, f);
            }
        }
        if (fmt.equals("serial")) {
            String source_address = source_addresses[0];
            context f = (lookup) -> lookup.call(source_address);
            BigInteger sequence = cb.get_txn_count(source_address, coin, testnet);
            Dict fields = new Dict();
            fields.put("TransactionType", BigInteger.ZERO); // Payment
            fields.put("Account", source_address);
            fields.put("Destination", address);
            fields.put("Amount", amount);
            fields.put("Fee", fee);
            fields.put("Sequence", sequence);
            // fields.put("LastLedgerSequence", ledger_index + 8); // TODO review this parameter
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        if (fmt.equals("xdr")) {
            String source_address = source_addresses[0];
            context f = (lookup) -> lookup.call(source_address);
            BigInteger sequence = cb.get_txn_count(source_address, coin, testnet);
            BigInteger target_sequence = cb.get_txn_count(address, coin, testnet);
            BigInteger target_balance = cb.get_balance(address, coin, testnet);
            boolean exists = target_balance.compareTo(BigInteger.ZERO) > 0 || target_sequence.compareTo(BigInteger.ZERO) > 0;
            Dict operation = new Dict();
            operation.put("Type", exists ? "PAYMENT" : "CREATE_ACCOUNT");
            operation.put("Destination", address);
            operation.put("Amount", amount);
            Dict fields = new Dict();
            fields.put("Account", source_address);
            fields.put("Operations", new Dict[]{operation});
            fields.put("Fee", fee);
            fields.put("Sequence", sequence.add(BigInteger.ONE));
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        if (fmt.equals("raiblock")) {
            String source_address = source_addresses[0];
            Pair<BigInteger, String> t = Wallet.address_decode(source_address, coin, testnet);
            BigInteger h = t.l;
            String kind = t.r;
            String publickey = Binint.n2h(h, 32);
            context f = (lookup) -> lookup.call(source_address);
            String representative = Coins.attr("voting.representative", coin, testnet);
            Dict[] utxos = cb.get_utxos(source_address, coin, testnet);
            if (utxos.length == 0) throw new IllegalArgumentException("Insufficient balance");
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger index1 = o1.get("index");
                BigInteger index2 = o2.get("index");
                return index1.compareTo(index2);
            });
            Dict utxo = utxos[0];
            Dict[] _utxos = new Dict[utxos.length - 1];
            System.arraycopy(utxos, 1, _utxos, 0, _utxos.length);
            utxos = _utxos;
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger amount1 = o1.get("amount");
                BigInteger amount2 = o2.get("amount");
                return amount2.compareTo(amount1);
            });
            String previous = utxo.get("txnid");
            BigInteger balance = utxo.get("amount");
            List<byte[]> txns = new ArrayList<>();
            for (Dict _utxo : utxos) {
                if (balance.compareTo(amount) >= 0) break;
                balance = balance.add((BigInteger) _utxo.get("amount"));
                String link = (String) _utxo.get("txnid");
                byte[] work = (byte[]) cb.custom_call("work", Binint.h2n(previous).equals(BigInteger.ZERO) ? publickey : previous, coin, testnet);
                Dict fields = new Dict();
                fields.put("account", source_address);
                fields.put("previous", previous);
                fields.put("representative", representative);
                fields.put("balance", balance);
                fields.put("link", link);
                if (work != null) fields.put("work", work);
                byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
                previous = Transaction.txnid(txn, coin, testnet);
                txns.add(txn);
            }
            if (balance.compareTo(amount) < 0) throw new IllegalArgumentException("Insufficient balance");
            balance = balance.subtract(amount);
            t = Wallet.address_decode(address, coin, testnet);
            BigInteger a = t.l;
            kind = t.r;
            String link = Binint.n2h(a, 32);
            byte[] work = (byte[]) cb.custom_call("work", Binint.h2n(previous).equals(BigInteger.ZERO) ? publickey : previous, coin, testnet);
            Dict fields = new Dict();
            fields.put("account", source_address);
            fields.put("previous", previous);
            fields.put("representative", representative);
            fields.put("balance", balance);
            fields.put("link", link);
            if (work != null) fields.put("work", work);
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            txns.add(txn);
            return new Pair<>(txns.toArray(new byte[][]{}), f);
        }
        if (fmt.equals("liskdatablock")) {
            String source_address = source_addresses[0];
            context f = (lookup) -> lookup.call(source_address);
            int time = (int) (System.currentTimeMillis() / 1000);
            BigInteger timestamp = BigInteger.valueOf(time - 1464109200); // lisk epoch 2016-05-24T17:00:00.000Z
            Dict fields = new Dict();
            fields.put("timestamp", timestamp);
            fields.put("amount", amount);
            fields.put("recipient", address);
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        if (fmt.equals("wavestx")) {
            String source_address = source_addresses[0];
            context f = (lookup) -> lookup.call(source_address);
            BigInteger timestamp = BigInteger.valueOf(System.currentTimeMillis());
            String asset_id = Coins.attr("asset.id", "", coin, testnet);
            String fee_asset_id = Coins.attr("fee_asset.id", "", coin, testnet);
            Dict fields = new Dict();
            fields.put("timestamp", timestamp);
            fields.put("amount", amount);
            fields.put("fee", fee);
            fields.put("recipient", address);
            if (!asset_id.equals("")) fields.put("asset", asset_id);
            if (!fee_asset_id.equals("")) fields.put("fee_asset", fee_asset_id);
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        if (fmt.equals("cbor")) {
            List<Dict> list = new ArrayList<>();
            for (String source_address : source_addresses) {
                list.addAll(Arrays.asList(cb.get_utxos(source_address, coin, testnet)));
            }
            Dict[] utxos = list.toArray(new Dict[]{});
            Arrays.sort(utxos, (Dict o1, Dict o2) -> {
                BigInteger amount1 = o1.get("amount");
                BigInteger amount2 = o2.get("amount");
                return amount2.compareTo(amount1);
            });
            BigInteger balance = BigInteger.ZERO;
            for (int i = 1; i <= utxos.length; i++) {
                balance = balance.add(utxos[i - 1].get("amount"));
                if (balance.compareTo(amount.add(fee)) >= 0) {
                    Dict[] t = new Dict[i];
                    System.arraycopy(utxos, 0, t, 0, t.length);
                    utxos = t;
                    break;
                }
            }
            Dict[] _utxos = utxos;
            context f = (lookup) -> {
                Object[] params = new Object[_utxos.length];
                for (int i = 0; i < _utxos.length; i++) {
                    Dict utxo = _utxos[i];
                    params[i] = new Object[]{lookup.call(utxo.get("address")), utxo.get("amount")};
                }
                return params;
            };
            Dict[] inputs = new Dict[utxos.length];
            for (int i = 0; i < utxos.length; i++) {
                Dict utxo = utxos[i];
                Dict input = new Dict();
                input.put("txnid", utxo.get("txnid"));
                input.put("index", utxo.get("index"));
                inputs[i] = input;
            }
            BigInteger change = balance.subtract(amount.add(fee));
            if (change.compareTo(BigInteger.ZERO) < 0) throw new IllegalArgumentException("Insufficient balance");
            boolean has_change = change.compareTo(BigInteger.ZERO) > 0;
            Dict[] outputs = new Dict[has_change ? 2 : 1];
            Dict output = new Dict();
            output.put("amount", amount);
            output.put("address", address);
            outputs[0] = output;
            if (has_change) {
                output = new Dict();
                output.put("amount", change);
                output.put("address", change_address);
                outputs[1] = output;
            }
            Dict fields = new Dict();
            fields.put("inputs", inputs);
            fields.put("outputs", outputs);
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        if (fmt.equals("protobuf")) {
            Dict block = (Dict) cb.custom_call("block", null, coin, testnet);
            byte[] ref_block_bytes = Bytes.sub(Binint.n2b(block.get("height"), 8), 6, 8);
            byte[] ref_block_hash = Bytes.sub(Binint.h2b(block.get("hash")), 8, 16);
            BigInteger expiration = ((BigInteger) block.get("timestamp")).add(BigInteger.valueOf(5 * 60 * 1000));
            String source_address = source_addresses[0];
            context f = (lookup) -> lookup.call(source_address);
            Dict fields = new Dict();
            fields.put("ref_block_bytes", ref_block_bytes);
            fields.put("ref_block_hash", ref_block_hash);
            fields.put("expiration", expiration);
            fields.put("owner_address", source_address);
            fields.put("to_address", address);
            fields.put("amount", amount);
            byte[] txn = Transaction.transaction_encode(fields, coin, testnet);
            return new Pair<>(new byte[][]{txn}, f);
        }
        throw new IllegalArgumentException("Unknown format");
    }

    public static byte[] sign_rawtxn(byte[] rawtxn, Object params, String coin, boolean testnet) {
        return Transaction.transaction_sign(rawtxn, params, coin, testnet);
    }

    public static String transfer_funds(Object _signing_data, Object _source_addresses, String address, BigInteger amount, BigInteger fee, String change_address, String coin, boolean testnet, callback cb) {
        if (!(_signing_data instanceof Object[])) _signing_data = new Object[]{ _signing_data };
        Object[] signing_data = (Object[]) _signing_data;
        if (!(_source_addresses instanceof String[])) _source_addresses = new String[]{ (String) _source_addresses };
        String[] source_addresses = (String[]) _source_addresses;
        Dict lookup = new Dict();
        for (int i = 0; i < source_addresses.length; i++) {
            lookup.put(source_addresses[i], signing_data[i]);
        }
        Pair<byte[][], context> t = create_rawtxn(source_addresses, address, amount, fee, change_address, coin, testnet, cb);
        byte[][] txns = t.l;
        context f = t.r;
        Object params = f.call(lookup::get);
        String txnid = null;
        for (byte[] txn : txns) {
            byte[] signedtxn = sign_rawtxn(txn, params, coin, testnet);
            txnid = cb.broadcast_txn(signedtxn, coin, testnet);
        }
        return txnid;
    }

    public interface context { Object call(lookup l); }
    public interface lookup { String call(String address); }

}
