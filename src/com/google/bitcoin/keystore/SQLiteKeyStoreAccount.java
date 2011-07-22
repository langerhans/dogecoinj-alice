/**
 * Copyright 2011 John Sample
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

/**
 * SQLiteKeyStoreAccount provides additional organizational information for 
 * keys in a {@link SQLiteKeyStore}
 */
public class SQLiteKeyStoreAccount {
    private int id;
    private String name;
    private byte[] encryptedKey;
    private byte[] keyHash;
    
    public SQLiteKeyStoreAccount(int id, String name, byte[] encryptedKey, byte[] keyHash) {
        this.id = id;
        this.name = name;
        this.encryptedKey = encryptedKey;
        this.keyHash = keyHash;
    }
    
    public int getID() {
        return id;
    }
    
    public String getName() {
        return name;
    }
    
    public byte[] getEncryptedKey() {
        return encryptedKey;
    }
    
    public byte[] getKeyHash() {
        return keyHash;
    }
    
    @Override
    public String toString() {
        return String.format("%s (ID: %s)", this.id, this.name);
    }
}
