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
import java.security.KeyStoreException;
import java.security.SecureRandom;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import com.google.bitcoin.core.*;

/**
 * SQLiteKeyStore is currently only for demo purposes and should not be
 * considered fit for production use.
 * 
 * If the encryption option is chosen all private keys will be encrypted with a
 * key per account. Account passwords can be changed at a later date by
 * re-encrypting just the account key vs each individual signing key. In
 * encrypted mode each account has an associated AES256 key which in turn is
 * also AES256 encrypted to a user provided password. The password is expanded
 * to 256 bits with a SHA256 hash. A SHA256 hash of the private account key is
 * stored to confirm proper account key decryption.
 * 
 * NOTE: In encrypted mode a {@link SQLiteKeyStoreEventListener} must be
 * provided to respond to password requests.
 */
public class SQLiteKeyStore implements KeyStore {

    private Connection conn = null;
    private SQLiteKeyStoreEventListener eventListener;
    private boolean encrypted;

    // Crude cache of account keys so we only have to ask once.
    private HashMap<String, byte[]> cachedKeys = new HashMap<String, byte[]>();

    /**
     * Creates a key store at the given location.
     */
    public static SQLiteKeyStore create(String path, boolean encrypted)
            throws ClassNotFoundException, SQLException {
        Class.forName("org.sqlite.JDBC");
        Connection connection = DriverManager.getConnection("jdbc:sqlite:"
                + path);
        Statement statement = connection.createStatement();

        int encrypt = encrypted ? 1 : 0;

        String sql = "BEGIN TRANSACTION;\n"
                + "CREATE TABLE settings (set_encrypted INTEGER);"
                + "INSERT INTO settings (set_encrypted) values (" + encrypt + ");"
                + "CREATE TABLE account (acc_id INTEGER PRIMARY KEY, acc_name TEXT UNIQUE, acc_key TEXT, acc_key_hash);\n"
                + "CREATE TABLE key (key_acc_id NUMERIC, key_id INTEGER PRIMARY KEY, key_private TEXT, key_public TEXT, key_hash TEXT, key_priv_hash);\n"
                + "CREATE INDEX keypubIdx on key (key_public);"
                + "CREATE INDEX keyhashIdx on key (key_hash);" + "COMMIT;";

        statement.executeUpdate(sql);
        connection.close();

        return new SQLiteKeyStore(path);

    }

    /**
     * Loads an existing {@link SQLiteKeyStore} from disk.
     */
    public SQLiteKeyStore(String path) throws SQLException,
            ClassNotFoundException {
        Class.forName("org.sqlite.JDBC");
        conn = DriverManager.getConnection("jdbc:sqlite:" + path);
        initSettings();
    }

    /**
     * Loads params from the settings table. Currently on the encrypted option
     * is stored.
     */
    private void initSettings() {
        try {
            Statement stat = conn.createStatement();
            ResultSet rs = stat.executeQuery("select * from settings");
            while (rs.next()) {
                encrypted = (rs.getInt("set_encrypted") == 1);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Allows the caller to learn about key store events and respond to password
     * requests. NOTE: This must be set in encrypted mode.
     */
    public void setEventListener(SQLiteKeyStoreEventListener listener) {
        eventListener = listener;
    }

    /**
     * Constructs keys from database records. The key queries also contain
     * enough information to build the account object if needed.
     */
    private SQLiteECKey keyFromRecord(ResultSet rs) throws KeyStoreException,
            SQLException {
        byte[] privateKey = rs.getBytes("key_private");
        if (encrypted) {
            privateKey = cryptForAccount(privateKey, accountFromRecord(rs),
                    false);
        }
        return new SQLiteECKey(new BigInteger(privateKey), rs.getInt("key_id"),
                rs.getInt("acc_id"), rs.getString("acc_name"));
    }

    /**
     * Constructs account objects from queries.
     */
    private SQLiteKeyStoreAccount accountFromRecord(ResultSet rs)
            throws SQLException {
        return new SQLiteKeyStoreAccount(rs.getInt("acc_id"),
                rs.getString("acc_name"), rs.getBytes("acc_key"),
                rs.getBytes("acc_key_hash"));
    }

    /**
     * Adds a key and returns the stored version. Key will be encrypted with the
     * given account's key if operating in encrypted mode.
     */
    public SQLiteECKey addKey(ECKey key, int account) throws KeyStoreException {
        String sql = "insert into Key (key_acc_id, key_private, key_public, key_hash, key_priv_hash) values (?,?,?,?,?)";

        byte[] keyPrivate = key.getPrivateKey().toByteArray();
        byte[] keyPrivHash = null;

        if (encrypted) {
            byte[] accountKey = retrieveAccountKey(getAccount(account));
            keyPrivHash = new Sha256Hash(keyPrivate).getBytes();
            keyPrivate = Utils.aes256(keyPrivate, accountKey, true);
        }

        try {
            PreparedStatement stat = conn.prepareStatement(sql);
            stat.setInt(1, account);
            stat.setBytes(2, keyPrivate);
            stat.setBytes(3, key.getPubKey());
            stat.setBytes(4, key.getPubKeyHash());
            stat.setBytes(5, keyPrivHash);
            stat.executeUpdate();
        } catch (SQLException e) {
            throw new KeyStoreException(e);
        }

        return findKeyFromPubKey(key.getPubKey());
    }

    /**
     * Adds a new account to the key store. Accounts can contain many keys. If
     * operating in encrypted mode a random 256 bit key will be used to encrypt
     * all keys belonging to this account. The store will call
     * onAccountPasswordCreate in {@link SQLiteKeyStoreEventListener} to assign
     * the password protecting this key.
     */
    public SQLiteKeyStoreAccount addAccount(String name)
            throws KeyStoreException {

        byte[] encryptedKey = null;
        byte[] accountKeyHash = null;

        // If encryption is set on the store we need to generate a new key
        if (encrypted) {
            assert eventListener != null : "Encrypted key store requires a password event handler.";

            // Calculate a key to encrypt the private keys then encrypt that key
            // with a password.
            byte[] accountKey = new byte[32];
            new SecureRandom().nextBytes(accountKey);
            // When we decrypt the key we won't know if the password was correct
            // unless we have a reference hash.
            accountKeyHash = new Sha256Hash(accountKey).getBytes();

            String password = eventListener.onAccountPasswordCreate(name);
            assert password != null;
            encryptedKey = Utils.aes256(accountKey, password, true);
        }

        PreparedStatement stat;
        try {
            stat = conn.prepareStatement("insert into Account (acc_name, acc_key, acc_key_hash) values (?,?,?)");
            stat.setString(1, name);
            stat.setBytes(2, encryptedKey);
            stat.setBytes(3, accountKeyHash);
            stat.executeUpdate();

        } catch (SQLException e) {
            throw new KeyStoreException(e);
        }
        return getAccount(name);
    }

    /**
     * Returns the given account if it exists or null if it doesn't.
     */
    public SQLiteKeyStoreAccount getAccount(String name)
            throws KeyStoreException {
        try {
            PreparedStatement stat = conn
                    .prepareStatement("select * from Account where acc_name = ?");
            stat.setString(1, name);
            ResultSet rs = stat.executeQuery();
            SQLiteKeyStoreAccount account = null;
            if (rs.next()) {
                account = accountFromRecord(rs);
            }
            // TODO : throw an exception if there isn't a single result
            rs.close();
            return account;
        } catch (SQLException e) {
            throw new KeyStoreException(e);
        }
    }

    /**
     * Returns the given account if it exists or null if it doesn't.
     */
    public SQLiteKeyStoreAccount getAccount(int id) throws KeyStoreException {
        try {
            PreparedStatement stat = conn
                    .prepareStatement("select * from Account where acc_id = ?");
            stat.setInt(1, id);
            ResultSet rs = stat.executeQuery();
            SQLiteKeyStoreAccount account = null;
            if (rs.next()) {
                account = accountFromRecord(rs);
            }
            // TODO : throw an exception if there isn't a single result
            rs.close();
            return account;
        } catch (SQLException e) {
            throw new KeyStoreException(e);
        }
    }

    /**
     * Returns all the keys in the key store.
     */
    public SQLiteKeyStoreAccount[] getAccounts() throws KeyStoreException {
        ArrayList<SQLiteKeyStoreAccount> accounts = new ArrayList<SQLiteKeyStoreAccount>();
        try {
            Statement stat = conn.createStatement();
            ResultSet rs = stat.executeQuery("select * from Account");

            while (rs.next()) {
                accounts.add(accountFromRecord(rs));
            }
            rs.close();

        } catch (SQLException e) {
            return null;
        }
        return accounts.toArray(new SQLiteKeyStoreAccount[] {});
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

        } catch (Exception e) {
            return null;
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

        } catch (Exception e) {
            return null;
        }
        return key;
    }

    @Override
    public boolean isPubKeyMine(byte[] pubKey) {
        return findKeyFromPubKey(pubKey) != null;
    }

    @Override
    public byte[] sign(byte[] input, StoredKey withKey) {
        // Our StoredKey implementation is just ECKey so it can be used directly
        // to sign.
        return ((ECKey) withKey).sign(input);
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

        } catch (Exception e) {
            return null;
        }
        return keys.toArray(new SQLiteECKey[] {});
    }

    public SQLiteECKey[] getKeysForAccount(int accountID)
            throws KeyStoreException {
        return getKeysForAccount(new int[] { accountID });
    }

    public SQLiteECKey[] getKeysForAccount(int[] accountID)
            throws KeyStoreException {
        String sql = "select * from Key, Account where key_acc_id = acc_id and acc_id in ("
                + generateParamsForIn(accountID.length) + ")";
        ArrayList<ECKey> keys = new ArrayList<ECKey>();

        try {
            PreparedStatement stat = conn.prepareStatement(sql);
            for (int i = 0; i < accountID.length; i++) {
                stat.setInt(i + 1, accountID[i]);
            }
            ResultSet rs = stat.executeQuery();
            while (rs.next()) {
                keys.add(keyFromRecord(rs));
            }

        } catch (Exception e) {
            throw new KeyStoreException(e);
        }

        return keys.toArray(new SQLiteECKey[] {});
    }

    // This call can create arbitrary length in(?,?,?...) parameters for sqlite
    // queries.
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

    /**
     * Inicates whether private keys in this key store are encrypted or stored
     * in plain text.
     * 
     * @return
     */
    public boolean isEncrypted() {
        return encrypted;
    }

    /**
     * Removes the decrypted key references from the key store. Passwords will
     * be re-requested on the next time they are needed.
     */
    public void clearKeyCache() {
        cachedKeys = new HashMap<String, byte[]>();
    }

    /**
     * Either retrieves the account AES key from the cache or retrieves it from
     * the caller.
     */
    private byte[] retrieveAccountKey(SQLiteKeyStoreAccount account)
            throws KeyStoreException {
        byte[] key = cachedKeys.get(account.getName());
        // If the key isn't cached it needs to be retrieved.
        if (key == null) {
            String password = eventListener.onAccountPasswordRequest(account);
            key = Utils.aes256(account.getEncryptedKey(), password, false);
            byte[] keyHash = new Sha256Hash(key).getBytes();
            if (!Arrays.equals(keyHash, account.getKeyHash())) {
                throw new KeyStoreException("Incorrect password for account");
            }
            cachedKeys.put(account.getName(), key);
        }
        return key;
    }

    /**
     * Handles encrypting or decrypting data to an account key including key
     * retrieval.
     */
    private byte[] cryptForAccount(byte[] data, SQLiteKeyStoreAccount account,
            boolean forEncryption) throws KeyStoreException {
        return Utils.aes256(data, retrieveAccountKey(account), forEncryption);
    }

}
