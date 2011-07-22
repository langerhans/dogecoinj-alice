/**
 * Copyright 2011 Thilo Planz
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

package com.google.bitcoin.core;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.fail;
import static org.junit.Assert.assertArrayEquals;

import java.security.SecureRandom;

import static com.google.bitcoin.core.Utils.*;

import org.junit.Test;

import com.google.bitcoin.bouncycastle.crypto.DataLengthException;
import com.google.bitcoin.bouncycastle.crypto.InvalidCipherTextException;


public class UtilsTest {

    @Test
    public void testToNanoCoins() {
        // String version
        assertEquals(CENT, toNanoCoins("0.01"));
        assertEquals(CENT, toNanoCoins("1E-2"));
        assertEquals(COIN.add(Utils.CENT), toNanoCoins("1.01"));
        try {
            toNanoCoins("2E-20");
            fail("should not have accepted fractional nanocoins");
        } catch (ArithmeticException e) {
        }

        // int version
        assertEquals(CENT, toNanoCoins(0, 1));

        // TODO: should this really pass?
        assertEquals(COIN.subtract(CENT), toNanoCoins(1, -1));
        assertEquals(COIN.negate(), toNanoCoins(-1, 0));
        assertEquals(COIN.negate(), toNanoCoins("-1"));
    }

    @Test
    public void testFormatting() {
        assertEquals("1.23", bitcoinValueToFriendlyString(toNanoCoins(1, 23)));
        assertEquals("-1.23", bitcoinValueToFriendlyString(toNanoCoins(1, 23).negate()));
    }
    
    @Test
    public void testAES() {
        //256 bit encryption requires 32 byte key.
        byte[] key = new byte[32];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(key);
        
        //Use an oddball size for testing
        byte[] origData = new byte[300];
        rnd.nextBytes(origData);
        
        java.util.Arrays.copyOf(origData, origData.length);
        
        byte[] encrypted = Utils.aes256(origData, key, true);
        byte[] decrypted = Utils.aes256(encrypted, key, false);
        assertArrayEquals(origData, decrypted);
        
        //Now try a length less than the block size.
        origData = new byte[10];
        rnd.nextBytes(origData);
        encrypted = Utils.aes256(origData, key, true);
        decrypted = Utils.aes256(encrypted, key, false);
        assertArrayEquals(origData, decrypted);
     
    }
    
    @Test
    public void testAESStringKey() {
        
        String key = "aes short key !(&%^";
        
        SecureRandom rnd = new SecureRandom();
        //Use an oddball size for testing
        byte[] origData = new byte[476];
        rnd.nextBytes(origData);
        
        java.util.Arrays.copyOf(origData, origData.length);
        
        byte[] encrypted = Utils.aes256(origData, key, true);
        byte[] decrypted = Utils.aes256(encrypted, key, false);
        assertArrayEquals(origData, decrypted);
        
        //Now try a length less than the block size.
        origData = new byte[10];
        rnd.nextBytes(origData);
        encrypted = Utils.aes256(origData, key, true);
        decrypted = Utils.aes256(encrypted, key, false);
        assertArrayEquals(origData, decrypted);
    }
}
