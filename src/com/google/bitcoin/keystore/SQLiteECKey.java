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

import java.math.BigInteger;
import com.google.bitcoin.core.ECKey;

/**
 * SQLiteECKey wraps SQLite stored keys with additional organizational information.
 */
public class SQLiteECKey extends ECKey {

    private int ID;
    private String accountName;
    private int accountID;

    public int getID() {
        return ID;
    }
    
    public String getAccountName()
    {
        return accountName;
    }
    
    public int getAccountID()
    {
        return accountID;
    }
    
    public SQLiteECKey(BigInteger priv, int keyID, int accountID, String accountName) {
        super(priv);
        this.ID = keyID;
        this.accountID = accountID;
        this.accountName = accountName;
    }
    
    @Override
    public String toString()
    {
        return String.format("ID: %s\nAccount (ID): %s (%s)\nKey Hash: %s", ID, accountName, accountID, this.getPrivateKey());
    }
}
