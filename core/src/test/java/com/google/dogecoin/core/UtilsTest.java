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

package com.google.dogecoin.core;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class UtilsTest {

    @Test
    public void testToNanoCoins() {
        // String version
        Assert.assertEquals(Utils.CENT, Utils.toNanoCoins("0.01"));
        Assert.assertEquals(Utils.CENT, Utils.toNanoCoins("1E-2"));
        Assert.assertEquals(Utils.COIN.add(Utils.CENT), Utils.toNanoCoins("1.01"));
        try {
            Utils.toNanoCoins("2E-20");
            org.junit.Assert.fail("should not have accepted fractional nanocoins");
        } catch (ArithmeticException e) {
        }

        // int version
        Assert.assertEquals(Utils.CENT, Utils.toNanoCoins(0, 1));

        try {
            Utils.toNanoCoins(1, -1);
            fail();
        } catch (IllegalArgumentException e) {}
        try {
            Utils.toNanoCoins(-1, 0);
            fail();
        } catch (IllegalArgumentException e) {}
        try {
            Utils.toNanoCoins("-1");
            fail();
        } catch (ArithmeticException e) {}
    }

    @Test
    public void testFormatting() {
        Assert.assertEquals("1.00", Utils.bitcoinValueToFriendlyString(Utils.toNanoCoins(1, 0)));
        Assert.assertEquals("1.23", Utils.bitcoinValueToFriendlyString(Utils.toNanoCoins(1, 23)));
        Assert.assertEquals("0.001", Utils.bitcoinValueToFriendlyString(BigInteger.valueOf(Utils.COIN.longValue() / 1000)));
        Assert.assertEquals("-1.23", Utils.bitcoinValueToFriendlyString(Utils.toNanoCoins(1, 23).negate()));
    }
    
    /**
     * Test the bitcoinValueToPlainString amount formatter
     */
    @Test
    public void testBitcoinValueToPlainString() {
        // null argument check
        try {
            Utils.bitcoinValueToPlainString(null);
            org.junit.Assert.fail("Expecting IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Value cannot be null"));
        }

        Assert.assertEquals("0.0015", Utils.bitcoinValueToPlainString(BigInteger.valueOf(150000)));
        Assert.assertEquals("1.23", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("1.23")));

        Assert.assertEquals("0.1", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("0.1")));
        Assert.assertEquals("1.1", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("1.1")));
        Assert.assertEquals("21.12", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("21.12")));
        Assert.assertEquals("321.123", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("321.123")));
        Assert.assertEquals("4321.1234", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("4321.1234")));
        Assert.assertEquals("54321.12345", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("54321.12345")));
        Assert.assertEquals("654321.123456", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("654321.123456")));
        Assert.assertEquals("7654321.1234567", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("7654321.1234567")));
        try {
            Assert.assertEquals("87654321.12345678", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("87654321.12345678")));
            Assert.fail();  // More than MAX_MONEY
        } catch (Exception e) {}

        // check there are no trailing zeros
        Assert.assertEquals("1", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("1.0")));
        Assert.assertEquals("2", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("2.00")));
        Assert.assertEquals("3", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("3.000")));
        Assert.assertEquals("4", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("4.0000")));
        Assert.assertEquals("5", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("5.00000")));
        Assert.assertEquals("6", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("6.000000")));
        Assert.assertEquals("7", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("7.0000000")));
        Assert.assertEquals("8", Utils.bitcoinValueToPlainString(Utils.toNanoCoins("8.00000000")));
    }    
    
    @Test
    public void testReverseBytes() {
        Assert.assertArrayEquals(new byte[] {1,2,3,4,5}, Utils.reverseBytes(new byte[] {5,4,3,2,1}));
    }

    @Test
    public void testReverseDwordBytes() {
        Assert.assertArrayEquals(new byte[] {1,2,3,4,5,6,7,8}, Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, -1));
        Assert.assertArrayEquals(new byte[] {1,2,3,4}, Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, 4));
        Assert.assertArrayEquals(new byte[0], Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, 0));
        Assert.assertArrayEquals(new byte[0], Utils.reverseDwordBytes(new byte[0], 0));
    }
}
