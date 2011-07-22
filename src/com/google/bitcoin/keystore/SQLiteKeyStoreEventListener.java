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

import com.google.bitcoin.core.StoredKey;

/**
 * SQLiteKeyStoreEventListener allows us to respond to decryption requests and
 * learn when new keys are added to the store.
 * 
 * TODO: pass in a response object that allows a graceful cancellation.
 */
public abstract class SQLiteKeyStoreEventListener {

    /**
     * Called when the key store needs a password to decrypt the given account.
     * 
     * @param account
     * @return
     */
    public String onAccountPasswordRequest(SQLiteKeyStoreAccount account) {
        return null;
    }

    /**
     * Called when an account creation request requires the assignment of a
     * password.
     * 
     * @param accountName
     * @return
     */
    public String onAccountPasswordCreate(String accountName) {
        return null;
    }

    public void onKeyAdd(StoredKey key) {

    }
}
