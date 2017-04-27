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

    private static final byte LONGTERMKEY[] = {
        (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37,
        (byte) 0x38, (byte) 0x39, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};
    
    private static byte SESSIONKEY[] = {
        (byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53, (byte) 0x54, (byte) 0x55, (byte) 0x56, (byte) 0x57,
        (byte) 0x58, (byte) 0x59, (byte) 0x60, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x65};

    private static final byte TESTDATA[] = {
        (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
        (byte) 0x38, (byte) 0x39, (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45};

    private static short hashLength = 32;

    private static short DATALENGTH = 16;
    private static short KEYLENGTH = 16;
    private static short IVLENGTH = 16;
    private static short NONCELENGTH = 16;

    private static byte[] HMac = new byte[hashLength];

    //private static byte[] cryptPassword = SESSIONKEY;
    
    private static final byte[] PCID = {
        (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31,
        (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31};
    
    private static final byte[] CARDID = {
        (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32,
        (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32};

    private static byte[] generateHMAC(byte[] bufferIn) throws NoSuchAlgorithmException {

        byte[] apdubuf = bufferIn;
        byte[] bufferOut = new byte[hashLength];
        short dataLen = (short) bufferIn.length;

        byte ipad = 0x36;
        byte opad = 0x5c;

        byte[] opadK = new byte[dataLen];
        byte[] ipadK = new byte[dataLen];

        byte[] arrayCat = new byte[KEYLENGTH + dataLen];

        byte[] key = new byte[KEYLENGTH];

        key = SESSIONKEY;

        for (short i = 0; i < KEYLENGTH; i++) {
            ipadK[i] = (byte) (key[i] ^ ipad);
            opadK[i] = (byte) (key[i] ^ opad);
        }

        byte[] tempArray = new byte[KEYLENGTH + hashLength];

        System.arraycopy(opadK, 0, tempArray, 0, KEYLENGTH);

        System.arraycopy(ipadK, 0, arrayCat, 0, KEYLENGTH);

        System.arraycopy(apdubuf, 0, arrayCat, KEYLENGTH, dataLen);

        MessageDigest hash256;
        hash256 = MessageDigest.getInstance("SHA-256");
        byte[] hashsum1 = new byte[hash256.getDigestLength()];

        System.out.println("Length of hash = " + hash256.getDigestLength());

        if (hash256 != null) {
            hashsum1 = hash256.digest(arrayCat);
        }
        //System.out.println();
        //System.out.println("Generated HashSum1 is " + cardManager.bytesToHex(hashsum1));
        //System.out.println();
        System.arraycopy(hashsum1, 0, tempArray, KEYLENGTH, hashLength);

        if (hash256 != null) {
            bufferOut = hash256.digest(tempArray);
        }
        System.out.println();
        System.out.println("Generated HMAC is " + cardManager.bytesToHex(bufferOut));
        System.out.println();
        return (bufferOut);
    }
    
    private static byte[] Encrypt(byte[] messageIn, short flag) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
        short dataLen = (short) messageIn.length;

        //if ((messageIn.length % 16) != 0) ISOException.throwIt(15);
      
        byte[] byteDataToEncrypt = new byte[dataLen - IVLENGTH];
        byte[] key = new byte[KEYLENGTH];
        byte[] iv = new byte[IVLENGTH];

        Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/NoPadding");
        
        switch (flag){
            case 1: key = LONGTERMKEY; break;
            case 3: key = SESSIONKEY; break;
        }
        
        SecretKey dataKey = new SecretKeySpec(key, 0, key.length, "AES");

        System.arraycopy(messageIn, (short) 0, byteDataToEncrypt, (short) 0, (short)(dataLen - IVLENGTH));
        System.arraycopy(messageIn, (short)(dataLen - IVLENGTH), iv, (short) 0, IVLENGTH);
        aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, dataKey, new IvParameterSpec(iv));

        //Generate the Cipher Text
        byte[] byteCipherText = aesCipherForEncryption.doFinal(byteDataToEncrypt);
        
        return (byteCipherText);
    }
    
    private static byte[] Decrypt(byte[] messageIn, short flag) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        
        short dataLen = (short) messageIn.length;

        if ((messageIn.length % 16) != 0) 
            System.out.println("message for decryption not a multiple of 16 bytes");
      
        byte[] byteDataToDecrypt = new byte[dataLen - IVLENGTH];
        byte[] key = new byte[KEYLENGTH];
        byte[] iv = new byte[IVLENGTH];

        Cipher aesCipherForDecryption = Cipher.getInstance("AES/CBC/NoPadding");
        
        switch (flag){
            case 1: key = LONGTERMKEY; break;
            case 3: key = SESSIONKEY; break;
        }

        SecretKey secretKey = new SecretKeySpec(key, 0, key.length, "AES");

        System.arraycopy(messageIn, (short) 0, byteDataToDecrypt, (short) 0, (short)(dataLen - IVLENGTH));
        System.arraycopy(messageIn, (short)(dataLen - IVLENGTH), iv, (short) 0, IVLENGTH);
        aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        //Generate the Cipher Text
        byte[] byteClearText = aesCipherForDecryption.doFinal(byteDataToDecrypt);
        
        return (byteClearText);
    }

    private static byte[] generateSecureAPDU(byte[] messageIn) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        byte[] byteDataToEncrypt = new byte[messageIn.length];
        byteDataToEncrypt = messageIn;

        byte[] iv = new byte[IVLENGTH];

        SecureRandom prng;
        prng = new SecureRandom();
        prng.nextBytes(iv);

        System.out.println("IV =====" + cardManager.bytesToHex(iv));

        Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/NoPadding");

        //Convert the passowrd in byte[] into SecretKey format
        SecretKey dataKey = new SecretKeySpec(SESSIONKEY, 0, SESSIONKEY.length, "AES");

        aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, dataKey, new IvParameterSpec(iv));

        //Generate the Cipher Text
        byte[] byteCipherText = aesCipherForEncryption.doFinal(byteDataToEncrypt);

        String strCipherText = new String(byteCipherText);
        System.out.println("Cipher Text generated using AES is " + strCipherText);

        //MsgConcatIV = Encr(Message) || IV
        byte[] MsgConcatIV = new byte[messageIn.length + iv.length];
        System.arraycopy(byteCipherText, 0, MsgConcatIV, 0, messageIn.length);
        System.arraycopy(iv, 0, MsgConcatIV, messageIn.length, iv.length);
        
        byte[] msgIVHMAC = new byte[hashLength];
        
        msgIVHMAC = generateHMAC(MsgConcatIV);
        byte[] bufferOut = new byte[MsgConcatIV.length + hashLength];
        
        System.arraycopy(MsgConcatIV, 0, bufferOut, 0, MsgConcatIV.length);
        System.arraycopy(msgIVHMAC, 0, bufferOut, MsgConcatIV.length, hashLength);
        
        return (bufferOut);
    }
    
    private static byte[] verifySecureAPDU(byte[] messageIn) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        
        byte[] apdubuf = messageIn;
        short dataLen = (short) messageIn.length;
        
        short inMessageLength = (short)(dataLen - hashLength - IVLENGTH);
        byte[] receivedPassword = new byte[inMessageLength];
        
        byte[] inHMAC = new byte[hashLength];
        byte[] inMessageIV = new byte[inMessageLength + IVLENGTH];
        
        byte[] generatedHMAC = new byte[hashLength];
        
        System.arraycopy(apdubuf, (short) 0, inMessageIV, (short) 0, (short)(inMessageLength + IVLENGTH));

        //Util.arrayCopyNonAtomic(apdubuf, (short)(ISO7816.OFFSET_CDATA + inMessageLength + IVLENGTH), inHMAC, (short)0, hashLength );
        System.arraycopy(apdubuf, (short)(inMessageLength + IVLENGTH), inHMAC, (short) 0, hashLength);
        
        //Construct HMAC of Encr(MEssage) || IV
        generatedHMAC = generateHMAC(inMessageIV);
        
        byte compare = Util.arrayCompare(inHMAC, (short)0, generatedHMAC, (short) 0, hashLength);
        
        if (compare == 0){
            receivedPassword = Decrypt(inMessageIV, (short)3);
            return (receivedPassword);
        } else {
                System.out.println("Error in retrieving Password");
                return null;
        }
        
    }
    
    private static void establishSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, Exception{
        
        byte[] NoncePC = new byte[NONCELENGTH];

        SecureRandom prng;
        prng = new SecureRandom();
        prng.nextBytes(NoncePC);
        
        byte[] iv = new byte[IVLENGTH];

        prng = new SecureRandom();
        prng.nextBytes(iv);
        
        byte[] PCIDNonce = new byte[PCID.length + NONCELENGTH + IVLENGTH];
        System.arraycopy(PCID, 0, PCIDNonce, 0, PCID.length);
        System.arraycopy(NoncePC, 0, PCIDNonce, PCID.length, NONCELENGTH);
        
        //Append the IV to PCIDNonce for Encrypt function
        System.arraycopy(iv, 0, PCIDNonce, (PCID.length + NONCELENGTH), IVLENGTH);
        
        //System.out.println("PCIDNonceIV Length " + PCIDNonce.length);
        //System.out.println("PCIDNonceIV  " + cardManager.bytesToHex(PCIDNonce));
        
        byte[] encryptedPCIDNoncePC = Encrypt(PCIDNonce, (short)1);
        
        byte[] APDURequestPayload = new byte[encryptedPCIDNoncePC.length + IVLENGTH];
        System.arraycopy(encryptedPCIDNoncePC, 0, APDURequestPayload, 0, encryptedPCIDNoncePC.length);
        System.arraycopy(iv, 0, APDURequestPayload, encryptedPCIDNoncePC.length, IVLENGTH);
        
        //System.out.println("encryptedPCIDNoncePC  " + cardManager.bytesToHex(encryptedPCIDNoncePC));
        
        short additionalDataLen = (short) APDURequestPayload.length;
        byte apdu[];
        ResponseAPDU response = null;

        apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu[CardMngr.OFFSET_INS] = (byte) 0x80;
        apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
        apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

        if (additionalDataLen != 0) {
            System.arraycopy(APDURequestPayload, 0, apdu, CardMngr.OFFSET_DATA, APDURequestPayload.length);
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

        byte[] byteResponse = response.getBytes();

        System.out.println();
        System.out.println("************************************************************");
        if ((byteResponse[byteResponse.length - 2] == -112) && (byteResponse[byteResponse.length - 1] == 0)) {
            System.out.println("1st step of Session Key Successful");
            
            byte[] secureAPDUReplyPayload = new byte[byteResponse.length-2];
            System.arraycopy(byteResponse, 0, secureAPDUReplyPayload, (short)0, secureAPDUReplyPayload.length);
            
            byte[] clearAPDUReplyPayload = new byte[byteResponse.length - 2 - IVLENGTH];
            clearAPDUReplyPayload = Decrypt(secureAPDUReplyPayload, (short)1);
            
            //System.out.println("clearAPDUReplyPayload Length  " + clearAPDUReplyPayload.length);
            //System.out.println("clearAPDUReplyPayload  " + cardManager.bytesToHex(clearAPDUReplyPayload));
            
            byte[] receivedCARDID = new byte[CARDID.length];
            byte[] receivedNoncePC = new byte[NONCELENGTH];
            byte[] receivedNonceCARD = new byte[NONCELENGTH];
            
            System.arraycopy(clearAPDUReplyPayload, 0, receivedCARDID, 0, CARDID.length);
            System.arraycopy(clearAPDUReplyPayload, CARDID.length, receivedNoncePC, 0, NONCELENGTH);
            System.arraycopy(clearAPDUReplyPayload, (CARDID.length + NONCELENGTH), receivedNonceCARD, 0, NONCELENGTH);
            
            byte compareCARDID = Util.arrayCompare(receivedCARDID,(short) 0, CARDID, (short)0, (short) CARDID.length);
            byte compareNoncePC = Util.arrayCompare(receivedNoncePC,(short) 0, NoncePC, (short)0, (short) NONCELENGTH);
            
            if((compareCARDID == 0) & (compareNoncePC == 0)){
                for (short i = 0; i < NONCELENGTH; i++) {
                    SESSIONKEY[i] = (byte) (receivedNonceCARD[i] ^ receivedNoncePC[i]);
                }
                
                System.out.println("SESSIONKEY  " + cardManager.bytesToHex(SESSIONKEY));
                prng = new SecureRandom();
                prng.nextBytes(iv);
                
                byte[] clearNoncePCNonceCARD = new byte[NONCELENGTH + IVLENGTH];
                System.arraycopy(SESSIONKEY, 0, clearNoncePCNonceCARD, 0, NONCELENGTH);
                System.arraycopy(iv, 0, clearNoncePCNonceCARD, NONCELENGTH, IVLENGTH);
                
                byte[] secureNoncePCNonceCARD = Encrypt(clearNoncePCNonceCARD, (short)1);
                
                byte[] secureAPDUAckPayload = new byte[secureNoncePCNonceCARD.length + IVLENGTH];
                System.arraycopy(secureNoncePCNonceCARD, 0, secureAPDUAckPayload, 0, secureNoncePCNonceCARD.length);
                System.arraycopy(iv, 0, secureAPDUAckPayload, secureNoncePCNonceCARD.length, IVLENGTH);
                
                additionalDataLen = (short) secureAPDUAckPayload.length;
                response = null;

                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x81;
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

                if (additionalDataLen != 0) {
                    System.arraycopy(secureAPDUAckPayload, 0, apdu, CardMngr.OFFSET_DATA, secureAPDUAckPayload.length);
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
                if ((byteResponse[byteResponse.length - 2] == -112) && (byteResponse[byteResponse.length - 1] == 0)) {
                    System.out.println("Setting of Session Key Successful");
                }else{
                    System.out.println("Setting of Session Key Unsuccessful");
                }
                
            }else{
                 System.out.println("Comparison of IDs Unsuccessful");
            }          
            
        } else {
            System.out.println("Session Key Unsuccessful");
        }
        System.out.println("************************************************************");
        System.out.println();
    }

    public static void main(String[] args) {
        try {

            System.out.println();
            System.out.println("************************************************************");
            System.out.println("This is SimpleAPDU .......");
            System.out.println("************************************************************");
            System.out.println();
            
            
            /****************** Session Key Establishment  ***************************/
            try{
                establishSessionKey();
                System.out.println("SESSIONKEY  " + cardManager.bytesToHex(SESSIONKEY));
            }
            catch(Exception e){
                System.out.println("Failed to establish Session Key ");
            }
            

            /******************Encrypt PIN Data ***************************/
            
            byte[] byteDataToEncrypt = new byte[DATALENGTH];

            System.arraycopy(NEW_USER_PIN, 0, byteDataToEncrypt, 0, NEW_USER_PIN.length);
            for (short i = (short) NEW_USER_PIN.length; i < DATALENGTH; i++) {
                byteDataToEncrypt[i] = 0;
            }

            System.out.println("PIN Data " + cardManager.bytesToHex(byteDataToEncrypt));

            byte[] secureAPDUPayload;
            secureAPDUPayload = generateSecureAPDU(byteDataToEncrypt);
            
            System.out.println("secureAPDUPayload " + cardManager.bytesToHex(secureAPDUPayload));
            
            short additionalDataLen = (short) secureAPDUPayload.length;
            byte apdu[];
            ResponseAPDU response = null;

            apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            apdu[CardMngr.OFFSET_INS] = (byte) 0x5D;
            apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
            apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

            if (additionalDataLen != 0) {
                System.arraycopy(secureAPDUPayload, 0, apdu, CardMngr.OFFSET_DATA, secureAPDUPayload.length);
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

            byte[] byteResponse = response.getBytes();
            byte[] receivedPassword = new byte[SESSIONKEY.length];

            System.out.println();
            System.out.println("************************************************************");
            if ((byteResponse[byteResponse.length - 2] == -112) && (byteResponse[byteResponse.length - 1] == 0)) {
                System.out.println("Getting of Password Successful");
                byte[] receivedAPDUData = new byte[byteResponse.length-2];
                System.arraycopy(byteResponse, 0, receivedAPDUData, 0, receivedAPDUData.length);

                receivedPassword = verifySecureAPDU(receivedAPDUData);
                System.out.println("receivedPassword " + cardManager.bytesToHex(receivedPassword));
            } else {
                System.out.println("Getting of Password Unsuccessful");
            }
            System.out.println("************************************************************");
            System.out.println();
            
            
            /**
             * **************Send the Encrypted Data to Card *********
             */
            
            /*
            byte[] byteDataToEncrypt = KEY_32;
            byte[] dataHMAC = new byte[hashLength];

            dataHMAC = generateHMAC(byteDataToEncrypt);
            //String strHMac = new String(HMac);
            System.out.println("Generated HMAC is " + cardManager.bytesToHex(dataHMAC));

            additionalDataLen = (short) (byteDataToEncrypt.length);

            apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            apdu[CardMngr.OFFSET_INS] = (byte) 0x5C; //52 is for Setting the Encryption and Decrytption Key
            apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
            apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

            if (additionalDataLen != 0) {
                System.arraycopy(byteDataToEncrypt, 0, apdu, CardMngr.OFFSET_DATA, byteDataToEncrypt.length);
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
            if ((byteResponse[byteResponse.length - 2] == -112) && (byteResponse[byteResponse.length - 1] == 0)) {
                System.out.println("Decryption Successful");
            } else {
                System.out.println("Decryption Unsuccessful");
            }
            System.out.println("************************************************************");
            System.out.println();

            System.out.println("Received HMAC is " + cardManager.bytesToHex(byteResponse));*/

            /**
             * ********************************************************************************
             * additionalDataLen = (short)(byteCipherText.length + iv.length);
             *
             * apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
             * apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
             * apdu[CardMngr.OFFSET_INS] = (byte) 0x5B; //52 is for Setting the
             * Encryption and Decrytption Key apdu[CardMngr.OFFSET_P1] = (byte)
             * 0x10; apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
             * apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;              *
             *
             * if (additionalDataLen != 0){ System.arraycopy(byteCipherText, 0,
             * apdu, CardMngr.OFFSET_DATA, byteCipherText.length);
             * System.arraycopy(iv, 0, apdu, (short)(CardMngr.OFFSET_DATA +
             * byteCipherText.length), iv.length); }
             *
             * if (cardManager.ConnectToCard()) {
             *
             * cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
             *
             * response = cardManager.sendAPDU(apdu);
             *
             * cardManager.DisconnectFromCard(); } else { System.out.println();
             * System.out.println("************************************************************");
             * System.out.println("Failed to connect to card");
             * System.out.println("************************************************************");
             * System.out.println(); }
             *
             * byteResponse = response.getBytes();
             *
             * System.out.println();
             * System.out.println("************************************************************");
             * if((byteResponse[byteResponse.length-2]==-112) &&
             * (byteResponse[byteResponse.length-1] == 0)){
             * System.out.println("Decryption Successful"); } else
             * System.out.println("Decryption Unsuccessful");
             * System.out.println("************************************************************");
                System.out.println();
             */
            /**
             * **********************************************************************************************
             */
            /**
             * ****************Get the Password stored in JavaCard to
             * encrypt/decrypt the file ***************
             */
            /*
                
                additionalDataLen = (short) SESSIONKEY.length;
                apdu = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
                apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
                apdu[CardMngr.OFFSET_INS] = (byte) 0x53; 
                apdu[CardMngr.OFFSET_P1] = (byte) 0x10;
                apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
                apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;   
                
                if (additionalDataLen != 0){
                    System.arraycopy(SESSIONKEY, 0, apdu, CardMngr.OFFSET_DATA, SESSIONKEY.length);
                }
                
                if (cardManager.ConnectToCard()) {
                    
                    cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                    
                    response = cardManager.sendAPDU(apdu);

                    cardManager.DisconnectFromCard();
                } else {
                    System.out.println("Failed to connect to card");
                }

                byteResponse = response.getBytes();
                short pwLen = (short) (byteResponse.length - 2);

                
                byte[] pw = new byte[pwLen];
                
                System.arraycopy(byteResponse, 0, pw, 0, pwLen);
                System.out.println("success1" + byteResponse.length);*/
                String password = new String(receivedPassword);
                System.out.println("success2");
                
                String fromPath1 = "/home/swatch/Desktop/Security_Technologies/Project/3.png";
                String toPath1 ="/home/swatch/Desktop/Security_Technologies/Project/3.aes";
                
                AESCrypt aes = new AESCrypt(true, password);
                aes.encrypt(2, fromPath1, toPath1);
		System.out.println("success");
                
                String fromPath2 = "/home/swatch/Desktop/Security_Technologies/Project/3.aes";
                String toPath2 ="/home/swatch/Desktop/Security_Technologies/Project/3decrypt.png";
                aes.decrypt(fromPath2, toPath2);
                
             
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
}
