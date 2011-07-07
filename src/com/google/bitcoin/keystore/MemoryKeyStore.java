/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.keystore;

import java.util.*;

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.StoredKey;

public class MemoryKeyStore implements KeyStore {

    public final ArrayList<ECKey> keychain;
    
    public MemoryKeyStore()
    {
        keychain = new ArrayList<ECKey>();
    }
    
    @Override
    public StoredKey addKey(ECKey key) {
        assert !keychain.contains(key);
        int insertIndex = keychain.size();
        keychain.add(insertIndex, key);
        return keychain.get(insertIndex);
    }

    @Override
    public void deleteKey(StoredKey key) {
        // TODO Auto-generated method stub

    }

    @Override
    public StoredKey findKeyFromPubHash(byte[] pubkeyHash) {
        for (ECKey key : keychain) {
            if (Arrays.equals(key.getPubKeyHash(), pubkeyHash)) return key;
        }
        return null;
    }

    @Override
    public boolean isPubKeyHashMine(byte[] pubkeyHash) {
        return findKeyFromPubHash(pubkeyHash) != null;
    }

    @Override
    public StoredKey findKeyFromPubKey(byte[] pubKey) {
        for (ECKey key : keychain) {
            if (Arrays.equals(key.getPubKey(), pubKey)) return key;
        }
        return null;
    }

    @Override
    public boolean isPubKeyMine(byte[] pubKey) {
        return findKeyFromPubKey(pubKey) != null;
    }

    @Override
    public StoredKey getKeyForTransactionChange() {
        assert keychain.size() > 0 : "Can't send value without an address to use for receiving change";
        return null;
    }

    @Override
    public byte[] sign(byte[] input, StoredKey withKey) {
        //Since we know we are passing ECKeys back just call sign() on the key
        return ((ECKey)withKey).sign(input);
    }

    @Override
    public StoredKey[] Keys() {
        return keychain.toArray(new ECKey[]{});
    }

}
