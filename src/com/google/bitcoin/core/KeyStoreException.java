package com.google.bitcoin.core;

public class KeyStoreException extends Exception {

    public KeyStoreException() {
        super();
    }
    
    public KeyStoreException(String message) {
        super(message);
    }
    
    public KeyStoreException(Throwable arg0)
    {
        super(arg0);
    }
    
    public KeyStoreException(String message, Throwable arg0) {
        super(message, arg0);
    }
    
}
