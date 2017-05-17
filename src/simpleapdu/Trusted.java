package simpleapdu;

import java.util.Arrays;
import javax.smartcardio.ResponseAPDU;
import java.security.*;
import javacard.framework.*;
import javax.crypto.*;
import com.licel.jcardsim.io.*;
import javax.crypto.spec.*;

public class Trusted {
    static CardMngr cardManager = new CardMngr();

    private static byte DEFAULT_USER_PIN[] = {(byte) 0, (byte) 0, (byte) 0, (byte) 0};
    
    private static byte NEW_USER_PIN[] = {(byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31};
    
    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    private static byte SELECT_SIMPLEAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    private static final byte LONGTERMKEY[] = {
        (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37,
        (byte) 0x38, (byte) 0x39, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};
    
    private static final byte PASSWORD[] = {
        (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
        (byte) 0x48, (byte) 0x49, (byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53, (byte) 0x54, (byte) 0x55};
    
     private static final byte TESTDATA[] = {
        (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
        (byte) 0x38, (byte) 0x39, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};
    
    public static void main(String[] args) {
        try {
                System.out.println();
                System.out.println("************************************************************");
                System.out.println("You are in Trusted Environment.......");
                System.out.println("************************************************************");
                System.out.println();
                
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();
            
                /************************************** Set a default User PIN *********************************/
                
                short additionalDataLen = 0;
                byte apdu[];

                short maxPINLength = (short) 4;
                additionalDataLen = (short)(maxPINLength + maxPINLength);
                //additionalDataLen = maxPINLength;
                
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x56; //56 is for Setting the PIN
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

                if (additionalDataLen != 0){
                    System.arraycopy(DEFAULT_USER_PIN, 0, apdu, CardMngr.OFFSET_DATA, maxPINLength);
                    //System.arraycopy(NEW_USER_PIN, 0, apdu, CardMngr.OFFSET_DATA, maxPINLength);
                    System.arraycopy(NEW_USER_PIN, 0, apdu, (short)(CardMngr.OFFSET_DATA + (short) 4), maxPINLength);
                }
                
                /************ Comn with Card ***************/
                ResponseAPDU response = null;

                if (cardManager.ConnectToCard()) {
                    // Select our application on card
                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);

                    // TODO: send proper APDU
                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println();
                    System.out.println("************************************************************");
                    System.out.println("Failed to connect to card");
                    System.out.println("************************************************************");
                    System.out.println();
                }

                /******************************************/

                byte[] byteResponse = response.getBytes();

                System.out.println();
                System.out.println("************************************************************");
                if((byteResponse[0] == -112) &&  (byteResponse[1] == 0)){
                    System.out.println("Setting of PIN successful");
                }
                else
                    System.out.println("Setting of PIN Unsuccessful");
                System.out.println("************************************************************");
                System.out.println();


                /***************************** Verifying the PIN ****************************************/

                additionalDataLen = (short) 4;
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x55; 
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

                if (additionalDataLen != 0){
                    System.arraycopy(NEW_USER_PIN, 0, apdu, CardMngr.OFFSET_DATA, (short) 4);
                }

                if (cardManager.ConnectToCard()) {

                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);

                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println();
                    System.out.println("************************************************************");
                    System.out.println("Failed to connect to card");
                    System.out.println("************************************************************");
                    System.out.println();
                }

                byteResponse = response.getBytes();

                System.out.println();
                System.out.println("************************************************************");
                if((byteResponse[0]== -112) &&  (byteResponse[1] == 0)){
                    System.out.println("Verification of PIN successful");
                }
                else
                    System.out.println("Verification of PIN Unsuccessful");
                System.out.println("************************************************************");
                System.out.println();

                /***************************Set the Long Term Key **********************************/
            
                //Take a password and Set it in the Card in Trusted Environment
          
                //TO BE CHANGED.................USE A HASH FUNCTION TO HASH THE PASSWORD BEFORE SETTING
                //byte[] LONGTERMKEY = secretKey.getEncoded(); 
                //byte[] LONGTERMKEY = KEY_16;

                //System.out.println("Encryption Decryption PW :" + cardManager.bytesToHex(LONGTERMKEY));
                
                additionalDataLen = (short) LONGTERMKEY.length;
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x52; //52 is for Setting the Encryption and Decrytption Key
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;             

                if (additionalDataLen != 0){
                    System.arraycopy(LONGTERMKEY, 0, apdu, CardMngr.OFFSET_DATA, LONGTERMKEY.length);
                }

                if (cardManager.ConnectToCard()) {
                    // Select our application on card
                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                    // TODO: send proper APDU
                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println();
                    System.out.println("************************************************************");
                    System.out.println("Failed to connect to card");
                    System.out.println("************************************************************");
                    System.out.println();
                }

                byteResponse = response.getBytes();

                System.out.println();
                System.out.println("************************************************************");
                if((byteResponse[0]==-112) &&  (byteResponse[1] == 0)){
                    System.out.println("Setting of Long Term Key successful");
                }
                else
                    System.out.println("Setting of Long Term Key Unsuccessful");
                System.out.println("************************************************************");
                System.out.println();
                
                /***************************Set the Application Password **********************************/
            
                //Take a password and Set it in the Card in Trusted Environment
          
                //TO BE CHANGED.................USE A HASH FUNCTION TO HASH THE PASSWORD BEFORE SETTING
                //byte[] LONGTERMKEY = secretKey.getEncoded(); 
                //byte[] LONGTERMKEY = KEY_16;

                //System.out.println("Encryption Decryption PW :" + cardManager.bytesToHex(LONGTERMKEY));
                
                additionalDataLen = (short) PASSWORD.length;
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x62; //52 is for Setting the Encryption and Decrytption Key
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;             

                if (additionalDataLen != 0){
                    System.arraycopy(PASSWORD, 0, apdu, CardMngr.OFFSET_DATA, PASSWORD.length);
                }

                if (cardManager.ConnectToCard()) {
                    // Select our application on card
                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                    // TODO: send proper APDU
                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println();
                    System.out.println("************************************************************");
                    System.out.println("Failed to connect to card");
                    System.out.println("************************************************************");
                    System.out.println();
                }

                byteResponse = response.getBytes();

                System.out.println();
                System.out.println("************************************************************");
                if((byteResponse[0]==-112) &&  (byteResponse[1] == 0)){
                    System.out.println("Setting of Application Password successful");
                }
                else
                    System.out.println("Setting of Application Password Unsuccessful");
                System.out.println("************************************************************");
                System.out.println();


        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
}
