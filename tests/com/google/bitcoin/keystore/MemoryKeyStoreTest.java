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
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import com.google.bitcoin.core.ECKey;


public class MemoryKeyStoreTest {

    private MemoryKeyStore keystore;
    private ECKey testKey;
    
    @Before
    public void setUp() throws IOException {
        keystore = new MemoryKeyStore();
        testKey = new ECKey();
    }
    
    @Test
    public void canRoundTrip() throws Exception {
        BigInteger originalPriv = testKey.getPrivateKey();
        keystore.addKey(testKey);
        File temp = newTempFile();
        keystore.saveToFile(temp);
        MemoryKeyStore reload = MemoryKeyStore.loadFromFile(temp);
        assertEquals(originalPriv, reload.keychain.get(0).getPrivateKey());
    }
    
    @Test
    public void canSign() throws IOException {
        File temp = newTempFile();
        keystore.addKey(testKey);
        //Round trip to disk first
        keystore.saveToFile(temp);
        MemoryKeyStore reload = MemoryKeyStore.loadFromFile(temp);
        
        byte[] signBytes = new byte[32];
        new Random().nextBytes(signBytes);
        
        //Sign with stored key, test with against unstored key.
        byte[] signed = reload.sign(signBytes, reload.getKeys()[0]);
        assertTrue(ECKey.verify(signBytes, signed, testKey.getPubKey()));
        
        //Try against a known bad key to make sure the keystore isn't always returning true
        assertFalse(ECKey.verify(signBytes, signed, new ECKey().getPubKey()));
    }
    
    private File newTempFile() {
        File temp = null;
        try {
            temp = File.createTempFile("bcj_mks","");
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return temp;
    }
}
