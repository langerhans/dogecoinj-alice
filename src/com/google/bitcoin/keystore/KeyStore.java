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

/**
 * The key half of a wallet.
 * The interface must provide access to the public half of a key but
 * allows the option of keeping the private portion hidden or remote.
 */

package com.google.bitcoin.keystore;

import com.google.bitcoin.core.*;

public interface KeyStore {
    
    //TODO: event notifications for key add, key invalidation, reload, etc...
    
    StoredKey addKey(ECKey key);
    void deleteKey(StoredKey key);
    
    StoredKey findKeyFromPubHash(byte[] pubkeyHash);
    boolean isPubKeyHashMine(byte[] pubkeyHash);
    StoredKey findKeyFromPubKey(byte[] pubKey);
    boolean isPubKeyMine(byte[] pubKey);
    
    StoredKey getKeyForTransactionChange();
    
    byte[] sign(byte[] input, StoredKey withKey);
    
    /*Keys() is only here because of the toString() call in Wallet
     * I'm not sure its necessary to have the entire list returned outside 
     * the code controlling the concrete key store implementation. 
     * If it stays it should probably be changed to some sort of iterable to keep the memory footprint down.*/
    StoredKey[] Keys();
    
}
