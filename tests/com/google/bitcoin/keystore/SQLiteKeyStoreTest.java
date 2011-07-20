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

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Random;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import com.google.bitcoin.core.ECKey;


public class SQLiteKeyStoreTest {

    private SQLiteKeyStore store;
    private String dbPath;
    private ECKey testKey = new ECKey();
    
    @Before
    public void setup() throws IOException, ClassNotFoundException, SQLException
    {
        File temp = File.createTempFile("sqlks1", ".dat");
        dbPath = temp.getAbsolutePath();
        store = SQLiteKeyStore.create(dbPath);
        System.out.println(dbPath);
    }
    
    @Test
    public void create() throws Exception
    {
        
        SQLiteKeyStoreAccount[] accounts = store.getAccounts();
        assertEquals("Create failed. Default account not found.", 1, accounts.length);
        //Run twice to make sure the connection is staying open
        assertEquals("Second query failed. Check connection closure.", accounts.length, store.getAccounts().length);
        print(accounts[0].toString());
        
        //Make sure we can add an account
        SQLiteKeyStoreAccount newAccount = store.addAccount("Test Add");
        assertEquals("Account add failed.", newAccount.getID(), 2);
        
        accounts = store.getAccounts();
        assertEquals(accounts.length, 2);
        
        SQLiteKeyStore reload = new SQLiteKeyStore(dbPath);
        SQLiteKeyStoreAccount[] reloadAccounts = reload.getAccounts();
        assertEquals("Reload failed.", reloadAccounts.length, accounts.length);
        
        //Round trip a key.
        print("Test Key:\n" + testKey.toString());
        store.addKey(testKey, 1);
        ECKey storedKey = (ECKey)store.findKeyFromPubKey(testKey.getPubKey());
        print("Stored Key:\n" + storedKey.toString());
        assertEquals("Key did not round trip correctly.", storedKey.getPrivateKey(), testKey.getPrivateKey());
        
        //Test key ownership.
        assertTrue("Test key not detected by public key.",store.isPubKeyMine(testKey.getPubKey()));
        ECKey ephemeralKey = new ECKey();
        assertFalse("Store incorrectly reporting key presence by public key.", store.isPubKeyMine(ephemeralKey.getPubKey()));
        
        //Find key with hash.
        assertTrue("Test key not detected by hash.",store.isPubKeyHashMine(testKey.getPubKeyHash()));
        assertFalse("Store incorrectly reporting key presence by hash.", store.isPubKeyMine(ephemeralKey.getPubKeyHash()));
     
        //Make sure unstored and stored private keys match.
        ECKey signKey = (ECKey)store.findKeyFromPubHash(testKey.getPubKeyHash());
        assertEquals(testKey.getPrivateKey(), signKey.getPrivateKey());
        
        byte[] signBytes = new byte[32];
        new Random().nextBytes(signBytes);
        
        //Sign with stored key, test with against unstored key.
        byte[] signed = signKey.sign(signBytes);
        assertTrue(ECKey.verify(signBytes,signed, testKey.getPubKey()));
        
        //Add a new key. Assign it to the second account.
        ECKey secondKey = new ECKey();
        store.addKey(secondKey, 2);
        //Make sure there are only two keys so far.
        assertEquals("More than two keys in the store.", 2,store.getKeys().length);
        
        //Switch to sqlitekey
        SQLiteECKey[] allKeys = store.getKeys();
        for (SQLiteECKey sqliteECKey : allKeys) {
            print(sqliteECKey.toString());
        }
   
    }
    
    private void print(String message) {
        System.out.println(message);
    }
}
