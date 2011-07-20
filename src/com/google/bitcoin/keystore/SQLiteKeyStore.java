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
import java.sql.*;
import java.util.ArrayList;

import com.google.bitcoin.core.*;

/**
 *  SQLiteKeyStore is currently only for demo purposes and should not be considered fir
 *  for production use. 
 */
public class SQLiteKeyStore implements KeyStore {
    
    private Connection conn = null;

    public static SQLiteKeyStore create(String path) throws ClassNotFoundException, SQLException
    {        
        Class.forName("org.sqlite.JDBC");
        Connection connection =
          DriverManager.getConnection("jdbc:sqlite:" + path);
        Statement statement = connection.createStatement();
        
        String sql = "BEGIN TRANSACTION;\n" + 
        		"CREATE TABLE account (acc_id INTEGER PRIMARY KEY, acc_name TEXT UNIQUE);\n" + 
        		"INSERT INTO account VALUES(1,'Default');\n" + 
        		"CREATE TABLE key (key_acc_id NUMERIC, key_id INTEGER PRIMARY KEY, key_private TEXT, key_public TEXT, key_hash TEXT);\n" +
        		"CREATE INDEX keypubIdx on key (key_public);" +
        		"CREATE INDEX keyhashIdx on key (key_hash);" + 
        		"COMMIT;";
        
        statement.executeUpdate(sql);
        connection.close();

        return new SQLiteKeyStore(path);
        
    }
    
    public SQLiteKeyStore(String path) throws SQLException, ClassNotFoundException
    {
        Class.forName("org.sqlite.JDBC");
        conn = DriverManager.getConnection("jdbc:sqlite:" + path);
    }
    
    private SQLiteECKey keyFromRecord(ResultSet rs) throws SQLException {
        return new SQLiteECKey(new BigInteger(rs.getString("key_private")),rs.getInt("key_id"), rs.getInt("acc_id"), rs.getString("acc_name"));
    }
    
    private SQLiteKeyStoreAccount accountFromRecord(ResultSet rs) throws SQLException {
        return new SQLiteKeyStoreAccount(rs.getInt("acc_id"), rs.getString("acc_name"));
    }
    
    public void addKey(ECKey key, int account) {
        String sql = "insert into Key (key_acc_id, key_private, key_public, key_hash) values (?,?,?,?)";
        try {
            PreparedStatement stat = conn.prepareStatement(sql);
            stat.setInt(1, account);
            stat.setString(2, key.getPrivateKey().toString());
            stat.setBytes(3, key.getPubKey());
            stat.setBytes(4, key.getPubKeyHash());
            stat.executeUpdate();
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
    }
    
    public SQLiteKeyStoreAccount addAccount(String name) throws Exception {
        PreparedStatement stat = conn.prepareStatement("insert into Account (acc_name) values (?)");
        stat.setString(1, name);
        stat.executeUpdate();
        stat = conn.prepareStatement("select * from Account where acc_name = ?");
        stat.setString(1, name);
        ResultSet rs = stat.executeQuery();

        SQLiteKeyStoreAccount account = null;
        if (rs.next()) {
            account = accountFromRecord(rs);
        } 
        // TODO : throw an exception if there isn't a single result
        rs.close();
        return account;
    }
    
    public SQLiteKeyStoreAccount[] getAccounts() {
        ArrayList<SQLiteKeyStoreAccount> accounts = new ArrayList<SQLiteKeyStoreAccount>();
        try {
            Statement stat = conn.createStatement();
            ResultSet rs = stat.executeQuery("select acc_id, acc_name from Account");
            
            while (rs.next()) {
                accounts.add(accountFromRecord(rs));
            }
            rs.close();
            
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return accounts.toArray(new SQLiteKeyStoreAccount[]{});
    }
    
    @Override
    public SQLiteECKey findKeyFromPubHash(byte[] pubkeyHash) {
        String sql = "select * from Key, Account where key_acc_id = acc_id and key_hash = ?";
        SQLiteECKey key = null;
        try {
            PreparedStatement stat = conn.prepareStatement(sql);
            stat.setBytes(1, pubkeyHash);
            ResultSet rs = stat.executeQuery();
            while (rs.next()) {
                key = keyFromRecord(rs);
            }
            rs.close();
            
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return key;
    }

    @Override
    public boolean isPubKeyHashMine(byte[] pubkeyHash) {
        return findKeyFromPubHash(pubkeyHash) != null;
    }

    @Override
    public SQLiteECKey findKeyFromPubKey(byte[] pubKey) {
        String sql = "select * from Key, Account where key_acc_id = acc_id and key_public = ?";
        SQLiteECKey key = null;
        try {
            PreparedStatement stat = conn.prepareStatement(sql);
            stat.setBytes(1, pubKey);
            ResultSet rs = stat.executeQuery();
            while (rs.next()) {
                key = keyFromRecord(rs);
            }
            rs.close();
            
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return key;
    }

    @Override
    public boolean isPubKeyMine(byte[] pubKey) {
        return findKeyFromPubKey(pubKey) != null;
    }

    @Override
    public byte[] sign(byte[] input, StoredKey withKey) {
        //Our StoredKey implementation is just ECKey so it can be used directly to sign.
        return ((ECKey)withKey).sign(input);
    }

    @Override
    public SQLiteECKey[] getKeys() {
        String sql = "select * from Key, Account where key_acc_id = acc_id";
        ArrayList<ECKey> keys = new ArrayList<ECKey>();
        try {
            PreparedStatement stat = conn.prepareStatement(sql);
            ResultSet rs = stat.executeQuery();
            while (rs.next()) {
                keys.add(keyFromRecord(rs));
            }
            rs.close();
            
        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return keys.toArray(new SQLiteECKey[]{});
    }

    public SQLiteECKey[] getKeysForAccount(int accountID) {
        return getKeysForAccount(new int[]{accountID});
    }
    
    public SQLiteECKey[] getKeysForAccount(int[] accountID) {
        String sql = "select * from Key, Account where key_acc_id = acc_id and acc_id in (" 
                    + generateParamsForIn(accountID.length) + ")";
        ArrayList<ECKey> keys = new ArrayList<ECKey>();
        
        try {
            PreparedStatement stat  = conn.prepareStatement(sql);
            for (int i = 0; i < accountID.length; i++) {
                stat.setInt(i+1, accountID[i]);
            } 
            ResultSet rs = stat.executeQuery();
            while (rs.next()) {
                keys.add(keyFromRecord(rs));
            }

        } catch (SQLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return keys.toArray(new SQLiteECKey[]{});
    }
    
    //This call can create arbitrary length in(?,?,?...) parameters for sqlite queries.
    private String generateParamsForIn(int numParams) {
        String items = "";
        for (int i = 0; i < numParams; i++) {
            items += "?";
            if (i < numParams - 1) {
                items += ", ";
            }
        }
        return items;
    }
    
}
