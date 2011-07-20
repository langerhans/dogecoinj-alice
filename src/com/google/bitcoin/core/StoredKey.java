package com.google.bitcoin.core;

public abstract class StoredKey {
        
    protected transient byte[] pubKeyHash;
    
    /** Gets the hash160 form of the public key (as seen in addresses). */
    public byte[] getPubKeyHash() {
        if (pubKeyHash == null)
            pubKeyHash = Utils.sha256hash160(this.getPubKey());
        return pubKeyHash;
    }
    
    /**
     * Gets the raw public key value. This appears in transaction scriptSigs. Note that this is <b>not</b> the same
     * as the pubKeyHash/address.
     */    
    public abstract byte[] getPubKey();
    
    public String toString() {
        StringBuffer b = new StringBuffer();
        b.append("pub:").append(Utils.bytesToHexString(getPubKey()));
        return b.toString();
    }
    
    /**
     * Returns the address that corresponds to the public part of this ECKey. Note that an address is derived from
     * the RIPEMD-160 hash of the public key and is not the public key itself (which is too large to be convenient).
     */
    public Address toAddress(NetworkParameters params) {
        byte[] hash160 = Utils.sha256hash160(getPubKey());
        return new Address(params, hash160);
    }
    
    /**
     * Verifies the given ASN.1 encoded ECDSA signature against a hash using the public key.
     * @param data Hash of the data to verify.
     * @param signature ASN.1 encoded signature.
     */
    public boolean verify(byte[] data, byte[] signature) {
        return ECKey.verify(data, signature, getPubKey());
    }
}
