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
import java.util.Random;
import static org.junit.Assert.*;
import org.junit.Test;
import com.google.bitcoin.core.ECKey;


public class SQLiteKeyStoreTest {
    
    @Test
    public void testUnencrypted() throws Exception
    {
        ECKey testKey = new ECKey();
        
        File temp = File.createTempFile("sqlks", ".dat");
        SQLiteKeyStore store = SQLiteKeyStore.create(temp.getAbsolutePath(), false);
        
        assertFalse(store.isEncrypted());
        
        //Make sure we can add an account
        SQLiteKeyStoreAccount newAccount = store.addAccount("Test Add");
        assertEquals("Account add failed.", newAccount.getID(), 1);
        
        SQLiteKeyStoreAccount[] accounts = store.getAccounts();
        assertEquals("Create failed. Default account not found.", 1, accounts.length);
        //Run twice to make sure the connection is staying open
        assertEquals("Second query failed. Check connection closure.", accounts.length, store.getAccounts().length);
        print(accounts[0].toString());
        
        //Add another account
        store.addAccount("another account");

        accounts = store.getAccounts();
        assertEquals(accounts.length, 2);
        
        SQLiteKeyStore reload = new SQLiteKeyStore(temp.getAbsolutePath());
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
    
    @Test
    public void testEncrypted() throws Exception {
        File temp = File.createTempFile("sqlks", ".dat");
        SQLiteKeyStore store = SQLiteKeyStore.create(temp.getAbsolutePath(), true);
        assertTrue(store.isEncrypted());
        
        store.setEventListener(
                new SQLiteKeyStoreEventListener() {
                    @Override
                    public String onAccountPasswordCreate(String accountName) {
                        if (accountName.equals("default")) {
                            return "password";
                        } else if (accountName.equals("second account")) {
                            return "new password";
                        }
                        return null;
                    };
                    @Override
                    public String onAccountPasswordRequest(SQLiteKeyStoreAccount account) {
                        return onAccountPasswordCreate(account.getName());
                    }
                }
        );
        
        SQLiteKeyStoreAccount defaultAccount = store.addAccount("default");
        
        ECKey firstKey = new ECKey();
        SQLiteECKey storedFirstKey = store.addKey(firstKey, defaultAccount.getID());
        assertArrayEquals(firstKey.getPrivateKey().toByteArray(), storedFirstKey.getPrivateKey().toByteArray());
        //Woohoo! The key round tripped successfully!
        //Now add another key to this account to test multiples and the key cache.
        ECKey secondKey = new ECKey();
        SQLiteECKey storedSecondKey = store.addKey(secondKey, defaultAccount.getID());
        assertArrayEquals(secondKey.getPrivateKey().toByteArray(), storedSecondKey.getPrivateKey().toByteArray());
        
        //Add a new account with a new key.
        ECKey thirdKey = new ECKey();
        SQLiteKeyStoreAccount secondAccount = store.addAccount("second account");
        SQLiteECKey storedThirdKey = store.addKey(thirdKey, secondAccount.getID());
        assertArrayEquals(thirdKey.getPrivateKey().toByteArray(), storedThirdKey.getPrivateKey().toByteArray());
        
        //Make sure key add fails if we provide the wrong password.
        store.clearKeyCache();
        store.setEventListener(new SQLiteKeyStoreEventListener() {
            @Override
            public String onAccountPasswordRequest(SQLiteKeyStoreAccount account) {
                return "this isn't right";
            }
        }
        );
        
        try {
            store.addKey(new ECKey(), 1);
            fail("Should not have allowed us to add key with the wrong password.");
        } catch (Exception e) {
            //Expected.
        }
        
    }
    
    private void print(String message) {
        System.out.println(message);
    }
}
