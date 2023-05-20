package org.example.cryptography.twofish;

public class ConfigTwoFish {
    public static final int BUFFER_SIZE = 16;

    public static final int I_WHITEN = 0;
    public static final int O_WHITEN = I_WHITEN +  BUFFER_SIZE /4;
    public static final int SUBKEYS = O_WHITEN + BUFFER_SIZE /4;

}
