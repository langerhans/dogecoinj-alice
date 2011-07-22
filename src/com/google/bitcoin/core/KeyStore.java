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

/**
 * The key half of a wallet.
 * The interface must provide access to the public half of a key but
 * allows the option of keeping the private portion hidden or remote.
 * 
 * The interface does not guarantee the calling application will be able
 * to add keys to the wallet.
 */

package com.google.bitcoin.core;

public interface KeyStore {

    /**
     * Locates a keypair from the keychain given the hash of the public key.
     * This is needed when finding out which key we need to use to redeem a
     * transaction output.
     * 
     * @return StoredKey object or null if no such key was found.
     */
    StoredKey findKeyFromPubHash(byte[] pubkeyHash);

    /**
     * Returns true if this wallet contains a public key which hashes to the
     * given hash.
     */
    boolean isPubKeyHashMine(byte[] pubkeyHash);

    /**
     * Locates a keypair from the keychain given the raw public key bytes.
     * 
     * @return StoredKey or null if no such key was found.
     */
    StoredKey findKeyFromPubKey(byte[] pubKey);

    /**
     * Returns true if this wallet contains a keypair with the given public key.
     */
    boolean isPubKeyMine(byte[] pubKey);

    /**
     * Requests the KeyStore sign the input with the private half of the
     * StoredKey.
     */
    byte[] sign(byte[] input, StoredKey withKey);

    /**
     * Returns all the keys in the KeyStore. Be careful with high key counts and
     * low memory.
     */
    StoredKey[] getKeys();

}
