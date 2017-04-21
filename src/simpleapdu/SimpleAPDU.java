package simpleapdu;

import java.util.Arrays;
import javax.smartcardio.ResponseAPDU;
import java.security.*;
import javacard.framework.*;
import javax.crypto.*;
import com.licel.jcardsim.io.*;
import javax.crypto.spec.*;

/**
 *
 * @author xsvenda
 */
public class SimpleAPDU {
    static CardMngr cardManager = new CardMngr();

    private static byte DEFAULT_USER_PIN[] = {(byte) 0, (byte) 0, (byte) 0, (byte) 0};
    
    private static byte NEW_USER_PIN[] = {(byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31};
    
    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    private static byte SELECT_SIMPLEAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    private static final byte KEY_32[] = {
        (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37,
        (byte) 0x38, (byte) 0x39, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45,
        (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37,
        (byte) 0x38, (byte) 0x39, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};
    
    private static final byte KEY_16[] = {
        (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37,
        (byte) 0x38, (byte) 0x39, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};
    
     private static final byte TESTDATA[] = {
        (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
        (byte) 0x38, (byte) 0x39, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};
     
    private static final byte[] cryptPassword = KEY_16;
     
    void generateHMAC(byte[] buffer) throws NoSuchAlgorithmException {
        
        byte[] apdubuf = buffer;
        short dataLen = (short) buffer.length;
       
        byte ipad = 0x36;
        byte opad = 0x5c;

        byte[] opadK = new byte[dataLen];
        byte[] ipadK = new byte[dataLen];

        byte[] arrayCat = new byte[2 * dataLen];
        byte[] arrayFinal = new byte[2 * dataLen];

        byte[] key = new byte[dataLen];
        
        key = cryptPassword;

        for (short i = 0; i < dataLen; i++) {
            ipadK[i] = (byte) (key[i] ^ ipad);
            opadK[i] = (byte) (key[i] ^ opad);
        }
        
        byte[] tempArray = new byte[256];

        //Util.arrayCopyNonAtomic(opadK, (short) 0, m_ramArray, (short) 0, dataLen);
        System.arraycopy(opadK, 0, tempArray, 0, dataLen);
        // System.out.println("Y = K XOR OPAD " + CardMngr.bytesToHex(m_ramArray));

        //Util.arrayCopyNonAtomic(ipadK, (short) 0, arrayCat, (short) 0, dataLen);
        System.arraycopy(ipadK, 0, arrayCat, 0, dataLen);
        // System.out.println("K XOR IPAD " + CardMngr.bytesToHex(arrayCat));

        //Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, arrayCat, dataLen, dataLen);
        System.arraycopy(apdubuf, 0, arrayCat, dataLen, dataLen);
        // System.out.println("(K XOR IPAD) ||C " + CardMngr.bytesToHex(arrayCat));

        MessageDigest hash256;
        hash256 = MessageDigest.getInstance("SHA-256");
        byte[] hashsum1 = new byte[hash256.getDigestLength()];
        //byte[] hashsum2 = new byte[hash256.getDigestLength()];
        
        if (hash256 != null) {
            //hash256.doFinal(arrayCat, (short) 0, (short) ((short) 2 * dataLen), tempArray, dataLen);
            //System.out.println("Y||X = (K XOR OPAD) || X : " + CardMngr.bytesToHex(m_ramArray));
            hashsum1 = hash256.digest(arrayCat);
        }
        System.arraycopy(hashsum1, 0, tempArray, dataLen, dataLen);
        
        
        if (hash256 != null) {
            //m_hash.doFinal(m_ramArray, (short) 0, (short) (dataLen + (short) 20), arrayFinal, (short) 0);
            arrayFinal = hash256.digest(tempArray);
        }
        

    }

    
    public static void main(String[] args) {
        try {
                
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();
            
                /*************************** Set a default User PIN ***********************/
                
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
                    //System.arraycopy(DEFAULT_USER_PIN, 0, apdu, CardMngr.OFFSET_DATA, maxPINLength);
                    System.arraycopy(NEW_USER_PIN, 0, apdu, CardMngr.OFFSET_DATA, maxPINLength);
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
                    System.out.println("Failed to connect to card");
                }

                /******************************************/

                byte[] byteResponse = response.getBytes();

                //Check if the response received is correct or not
                System.out.println(Arrays.toString(byteResponse));

                if((byteResponse[0] == -112) &&  (byteResponse[1] == 0)){
                    System.out.println("Setting of PIN successfulhaha");
                }
                else
                    System.out.println("Setting of PIN Unsuccessfulhaha");



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
                    System.out.println("Failed to connect to card");
                }

                byteResponse = response.getBytes();

                if((byteResponse[0]== -112) &&  (byteResponse[1] == 0)){
                    System.out.println("Verification of PIN successful");
                }
                else
                    System.out.println("Verification of PIN Unsuccessful");

                /***************************Set the Encryption and Decryption Password **********************************/
            
                //Take a password and Set it in the Card in Trusted Environment
          
                //TO BE CHANGED.................USE A HASH FUNCTION TO HASH THE PASSWORD BEFORE SETTING
                //byte[] cryptPassword = secretKey.getEncoded(); 
                //byte[] cryptPassword = KEY_16;

                //System.out.println("Encryption Decryption PW :" + cardManager.bytesToHex(cryptPassword));
                
                additionalDataLen = (short) cryptPassword.length;
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x52; //52 is for Setting the Encryption and Decrytption Key
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;             

                if (additionalDataLen != 0){
                    System.arraycopy(cryptPassword, 0, apdu, CardMngr.OFFSET_DATA, cryptPassword.length);
                }

                if (cardManager.ConnectToCard()) {
                    // Select our application on card
                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                    // TODO: send proper APDU
                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println("Failed to connect to card");
                }

                byteResponse = response.getBytes();

                if((byteResponse[0]==-112) &&  (byteResponse[1] == 0)){
                    System.out.println("Setting of Encryption/ Decryption Key successful");
                }
                else
                    System.out.println("Setting of Encryption/ Decryption Key Unsuccessful");

                /******************Get the Password stored in JavaCard to encrypt/decrypt the file ****************************/
        
                additionalDataLen = 0;
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x53; 
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;   
                
                if (additionalDataLen != 0){
                    System.arraycopy(cryptPassword, 0, apdu, CardMngr.OFFSET_DATA, cryptPassword.length);
                }
                
                if (cardManager.ConnectToCard()) {
                    
                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                    
                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println("Failed to connect to card");
                }

                byteResponse = response.getBytes();
                
                if((byteResponse[byteResponse.length-1]==-112) &&  (byteResponse[byteResponse.length] == 0)){
                    System.out.println("Getting of Encryption/ Decryption Key successful");
                }
                else
                    System.out.println("Getting of Encryption/ Decryption Key Unsuccessful");
               
                
                /*************************************************************************************************/

                byte[] byteDataToEncrypt = TESTDATA;
                                
                /**************** AES Encryption ***************/
                
                                
                final int KEYLENGTH = 128;	
		byte[] iv = new byte[KEYLENGTH / 8];
                
		SecureRandom prng;
                prng = new SecureRandom();
		prng.nextBytes(iv);
                
                //String siv = new String(iv);
                System.out.println("IV =====" + cardManager.bytesToHex(iv));
                
                Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/NoPadding");
                
                SecretKey dataKey = new SecretKeySpec(cryptPassword, 0, cryptPassword.length, "AES");
                
                aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, dataKey, new IvParameterSpec(iv));
                        
		byte[] byteCipherText = aesCipherForEncryption.doFinal(byteDataToEncrypt);
                
                String strCipherText = new String(byteCipherText);
		System.out.println("Cipher Text generated using AES is " + strCipherText);
                
                /****************Send the Encrypted Data to Card **********/
                
                additionalDataLen =  (short)(byteCipherText.length + iv.length);
                
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x5B; //52 is for Setting the Encryption and Decrytption Key
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;    
                

                if (additionalDataLen != 0){
                    System.arraycopy(byteCipherText, 0, apdu, CardMngr.OFFSET_DATA, byteCipherText.length);
                    System.arraycopy(iv, 0, apdu, (short)(CardMngr.OFFSET_DATA + byteCipherText.length), iv.length);
                }

                if (cardManager.ConnectToCard()) {

                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);

                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println("Failed to connect to card");
                }

                byteResponse = response.getBytes();

                if((byteResponse[0]==-112) &&  (byteResponse[1] == 0)){
                    System.out.println("Setting of Encryption/ Decryption Key successful");
                }
                else
                    System.out.println("Setting of Encryption/ Decryption Key Unsuccessful");

                
                
                /*************************************************************************************************/

                /******************Get the Password stored in JavaCard to encrypt/decrypt the file ****************/
                
                
                
                /*
                additionalDataLen = 0;
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x53; 
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;   
                
                if (additionalDataLen != 0){
                    System.arraycopy(cryptPassword, 0, apdu, CardMngr.OFFSET_DATA, cryptPassword.length);
                }
                
                if (cardManager.ConnectToCard()) {
                    
                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                    
                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println("Failed to connect to card");
                }

                byteResponse = response.getBytes();

                
                byte[] pw = new byte[20];
                //for (int i=0; i<32; i++)
                  //  pw[i] = byteResponse[i+5];
                
                System.arraycopy(byteResponse, 0, pw, 0, 20);
                System.out.println("success1" + byteResponse.length);
                String password = new String(pw);
                System.out.println("success2");
                
                String fromPath1 = "/home/swatch/Desktop/Security_Technologies/Project/3.png";
                String toPath1 ="/home/swatch/Desktop/Security_Technologies/Project/3.aes";
                
                AESCrypt aes = new AESCrypt(true, password);
                aes.encrypt(2, fromPath1, toPath1);
		System.out.println("success");
                
                String fromPath2 = "/home/swatch/Desktop/Security_Technologies/Project/3.aes";
                String toPath2 ="/home/swatch/Desktop/Security_Technologies/Project/3decrypt.png";
                aes.decrypt(fromPath2, toPath2);*/
                
                
                
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
}
