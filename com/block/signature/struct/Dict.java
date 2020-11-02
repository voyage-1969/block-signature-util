package com.block.signature.struct;

import java.util.HashMap;
import java.util.Map;

public class Dict {

    private final Map<String, Object> map;

    public Dict() {
        map = new HashMap<>();
    }

    public Dict(Dict d) {
        map = new HashMap<>(d.map);
    }

    public boolean has(String key) {
        return map.containsKey(key);
    }

    @SuppressWarnings("unchecked")
    public <A> A get(String key) {
        if (!map.containsKey(key)) throw new IllegalArgumentException("Unknown key");
        return (A) map.get(key);
    }

    @SuppressWarnings("unchecked")
    public <A> A get(String key, A def) {
        return map.containsKey(key) ? (A) map.get(key) : def;
    }

    public <A> void put(String key, A value) {
        map.put(key, value);
    }

    public void del(String key) {
        if (!map.containsKey(key)) throw new IllegalArgumentException("Unknown key");
        map.remove(key);
    }

}
