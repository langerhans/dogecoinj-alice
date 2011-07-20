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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.*;

import com.google.bitcoin.core.*;


public class MemoryKeyStore implements KeyStore, Serializable {

    private static final long serialVersionUID = -8337862463609611142L;
    
    public final ArrayList<ECKey> keychain;
    
    public MemoryKeyStore()
    {
        keychain = new ArrayList<ECKey>();
    }
    
    public synchronized void saveToFile(File f) throws IOException {
        saveToFileStream(new FileOutputStream(f));
    }
    
    public synchronized void saveToFileStream(FileOutputStream f) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(f);
        oos.writeObject(this);
        oos.close();
    }
    
    /**
     * Returns a {@link MemoryKeyStore} deserialized from the given file.
     */
    public static MemoryKeyStore loadFromFile(File f) throws IOException {
        return loadFromFileStream(new FileInputStream(f));
    }

    /**
     * Returns a {@link MemoryKeyStore} deserialized from the given file input stream.
     */
    public static MemoryKeyStore loadFromFileStream(FileInputStream f) throws IOException {
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(f);
            return (MemoryKeyStore) ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } finally {
            if (ois != null) ois.close();
        }
    }
    
    public StoredKey addKey(ECKey key) {
        assert !keychain.contains(key);
        keychain.add(key);
        return key;
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
    public byte[] sign(byte[] input, StoredKey withKey) {
        //Since we know we are passing ECKeys back just call sign() on the key
        return ((ECKey)withKey).sign(input);
    }

    @Override
    public StoredKey[] getKeys() {
        return keychain.toArray(new ECKey[]{});
    }


}
