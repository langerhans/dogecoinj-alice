package com.google.bitcoin.core;

import com.google.bitcoin.keystore.KeyStore;

public class StoredKey {
    
    private KeyStore keyStore;
    
    protected byte[] pub;
    protected byte[] pubKeyHash;
    
    public KeyStore getKeyStore()
    {
        return keyStore;
    }
    
    /** Gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getPubKeyHash() {
        if (pubKeyHash == null)
            pubKeyHash = Utils.sha256hash160(this.pub);
        return pubKeyHash;
    }
    
    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is <b>not</b> the same
     * as the pubKeyHash/address.
     */
    public byte[] getPubKey() {
        return pub;
    }
    
    public String toString() {
        StringBuffer b = new StringBuffer();
        b.append("pub:").append(Utils.bytesToHexString(pub));
        return b.toString();
    }
    
    /**
     * Returns the address that corresponds to the public part of this ECKey. Note that an address is derived from
     * the RIPEMD-160 hash of the public key and is not the public key itself (which is too large to be convenient).
     */
    public Address toAddress(NetworkParameters params) {
        byte[] hash160 = Utils.sha256hash160(pub);
        return new Address(params, hash160);
    }
    
    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     * @param data Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     */
    public boolean verify(byte[] data, byte[] signature) {
        return ECKey.verify(data, signature, pub);
    }
}
