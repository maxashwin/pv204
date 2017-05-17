/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */
package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import javacard.framework.Util;

public class SimpleApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET                = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_ENCRYPT                    = (byte) 0x50;
    final static byte INS_DECRYPT                    = (byte) 0x51;

    final static byte INS_SETLONGTERMKEY             = (byte) 0x52;
    final static byte INS_SETPASSWORD                = (byte) 0x62;
    final static byte INS_SETKEY                     = (byte) 0x72;
    
    final static byte INS_ESTSESSIONKEY              = (byte) 0x80;
    final static byte INS_ACKSESSIONKEY              = (byte) 0x81;
    
    final static byte INS_GETKEY                     = (byte) 0x53;
    final static byte INS_RANDOM                     = (byte) 0x54;
    final static byte INS_VERIFYPIN                  = (byte) 0x55;
    final static byte INS_SETPIN                     = (byte) 0x56;
    final static byte INS_RETURNDATA                 = (byte) 0x57;
    final static byte INS_SIGNDATA                   = (byte) 0x58;
    final static byte INS_GETAPDUBUFF                = (byte) 0x59;
    final static byte INS_ENCRYPTDECRYPT             = (byte) 0x5B;
    final static byte INS_GENHMAC                    = (byte) 0x5C;
    final static byte INS_GETSCPWD                   = (byte) 0x5D;
    
    //Add a Instruction to handle user instructions
    final static byte INS_USERINPUT                  = (byte) 0x5A;

    final static short ARRAY_LENGTH                   = (short) 0xff;
    final static byte  AES_BLOCK_LENGTH               = (short) 0x16;
    
    final static short PINSize                        = (short) 4;
    final static short KeySize                        = (short) 16;

    final static short SW_BAD_TEST_DATA_LEN          = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD             = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD     = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE       = (short) 0x6711;
    final static short SW_BAD_PIN                    = (short) 0x6900;
    final static short BAD_SESSION1                  = (short) 0x7001;
    final static short BAD_SESSION2                   = (short) 0x7002;

   
    private   AESKey         m_aesLongTermKey = null;
    private   AESKey         m_aesPassword = null;
    private   AESKey         m_aesKey = null;
    
    private   RandomData     m_secureRandom = null;
    private   MessageDigest  m_hash = null;
    private   OwnerPIN       m_pin = null;
    private   Cipher         m_encryptCipher = null;
    private   Cipher         m_decryptCipher = null;
    private   Cipher         m_encryptLongTermCipher = null;
    private   Cipher         m_decryptLongTermCipher = null;

    // TEMPORARRY ARRAY IN RAM
    private   byte        m_ramArray[] = null;
    private   byte        m_NoncePC[] = null;
    private   byte        m_NonceCARD[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte       m_dataArray[] = null;
    
    private static short hashLength = (short) 32;
    private static short KEYLENGTH = (short)16;
    private static short IVLENGTH = (short)16;
    private static short NONCELENGTH = 16;
    
    private static final byte[] PCID = {
        (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31,
        (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31};
    
    private static final byte[] CARDID = {
        (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32,
        (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32, (byte) 0x32};
    
    private static final byte SESSIONKEY[] = {
        (byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53, (byte) 0x54, (byte) 0x55, (byte) 0x56, (byte) 0x57,
        (byte) 0x58, (byte) 0x59, (byte) 0x60, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x65};

    protected SimpleApplet(byte[] buffer, short offset, byte length)
    {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

            dataOffset++;

            //written into EEPROM, limited writes 
            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);
            
            m_NoncePC = new byte[NONCELENGTH];
            m_NonceCARD = new byte[NONCELENGTH];
            Util.arrayFillNonAtomic(m_NoncePC, (short) 0, NONCELENGTH, (byte) 0);
            Util.arrayFillNonAtomic(m_NonceCARD, (short) 0, NONCELENGTH, (byte) 0);

            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            m_aesLongTermKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            m_aesPassword = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            
            m_encryptLongTermCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptLongTermCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            
            // CREATE RANDOM DATA GENERATORS
             m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            // SET KEY VALUE
            m_aesKey.setKey(SESSIONKEY, (short) 0);
            m_aesLongTermKey.setKey(m_dataArray, (short) 0);
            m_aesPassword.setKey(m_dataArray, (short) 0);
            
            // INIT CIPHERS WITH NEW KEY like a default key
            m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
            
            //m_encryptLongTermCipher.init(m_aesLongTermKey, Cipher.MODE_ENCRYPT);
            //m_decryptLongTermCipher.init(m_aesLongTermKey, Cipher.MODE_DECRYPT);

            m_pin = new OwnerPIN((byte) 5, (byte) 4);
            m_pin.update(m_dataArray, (byte) 0, (byte) 4);

            try {
                m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            }
            catch (CryptoException e) {
               // HASH ENGINE NOT AVAILABLE
            }

            // update flag
            isOP2 = true;

        } else {
           // <IF NECESSARY, USE COMMENTS TO CHECK LENGTH >
           // if(length != <PUT YOUR PARAMETERS LENGTH> )
           //     ISOException.throwIt((short)(ISO7816.SW_WRONG_LENGTH + length));
       }
          register();
    }

    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new SimpleApplet (bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // <PUT YOUR SELECTION ACTION HERE>
        //Clean data
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {

        // <PUT YOUR DESELECTION ACTION HERE>
        //Clean data

        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {

        byte[] apduBuffer = apdu.getBuffer();

        if (selectingApplet())
            return;

        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_SETLONGTERMKEY: SetKey(apdu, (short) 1); break;
                case INS_SETPASSWORD: SetKey(apdu, (short) 2); break;
                case INS_SETKEY: SetKey(apdu, (short) 3); break;
                case INS_VERIFYPIN: VerifyPIN(apdu); break;
                case INS_SETPIN: SetPIN(apdu); break;
                case INS_ESTSESSIONKEY: establishSessionKey(apdu); break;
                case INS_ACKSESSIONKEY: acknowledgeSessionKey(apdu); break;
                case INS_GETSCPWD: getSecurePassword(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    // SET ENCRYPTION & DECRYPTION KEY
    void SetKey(APDU apdu, short flag) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
      
        if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_128) ISOException.throwIt(SW_KEY_LENGTH_BAD);
      
        switch (flag){
            case 1: m_aesLongTermKey.setKey(apdubuf, ISO7816.OFFSET_CDATA); break;
            case 2: m_aesPassword.setKey(apdubuf, ISO7816.OFFSET_CDATA); break;
            case 3: m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA); break;
        }
    }

    void VerifyPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      // VERIFY PIN
      if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false)
      ISOException.throwIt(SW_BAD_PIN);
    }

    // SET PIN....Old PIN to be verified. Anybody can set any value.
    void SetPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) PINSize )) {
          m_pin.update(apdubuf, (byte) (ISO7816.OFFSET_CDATA + 4), (byte) PINSize);
        }
      else{
          ISOException.throwIt(SW_BAD_PIN);
      }
    }
    
    void Decrypt(byte[] messageIn, short flag) {
        
        short dataLen = (short) messageIn.length;

        if ((messageIn.length % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);  
        
        switch (flag){
            case 1: 
                m_decryptLongTermCipher.init(m_aesLongTermKey, Cipher.MODE_DECRYPT, messageIn, (short)(dataLen - IVLENGTH), IVLENGTH);
                m_decryptLongTermCipher.doFinal(messageIn, (short) 0, (short)(dataLen - IVLENGTH), m_ramArray, (short) 0); 
                break;
            case 3: 
                m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT, messageIn, (short)(dataLen - IVLENGTH), IVLENGTH);
                m_decryptCipher.doFinal(messageIn, (short) 0, (short)(dataLen - IVLENGTH), m_ramArray, (short) 0);   
                break;
        }
    }
    
    void Encrypt(byte[] messageIn, short flag) {
        
        byte[] tempIV = JCSystem.makeTransientByteArray(IVLENGTH, JCSystem.CLEAR_ON_DESELECT);
        
        m_secureRandom.generateData(tempIV, (short) 0, IVLENGTH);

        if ((messageIn.length % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
   
        switch(flag){
            case 1:
                m_encryptLongTermCipher.init(m_aesLongTermKey, Cipher.MODE_ENCRYPT, tempIV, (short) 0, IVLENGTH);
                m_encryptLongTermCipher.doFinal(messageIn, (short) 0, (short)(messageIn.length), m_ramArray, (short) 0); 
                break;
            case 3:
                m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT, tempIV, (short) 0, IVLENGTH);
                m_encryptCipher.doFinal(messageIn, (short) 0, (short)(messageIn.length), m_ramArray, (short) 0); 
                break;
        }
        Util.arrayCopyNonAtomic(tempIV, (short) 0, m_ramArray, (short)(messageIn.length), IVLENGTH);
    }
    
    void establishSessionKey(APDU apdu) {
        
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        byte[] messageIV = JCSystem.makeTransientByteArray(dataLen, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, messageIV, (short) 0, dataLen);
        
        //byte[] encData = JCSystem.makeTransientByteArray(KEYLENGTH, JCSystem.CLEAR_ON_DESELECT);
        
        Decrypt(messageIV, (short) 1);
                
        byte compare = Util.arrayCompare(m_ramArray, (short)0, PCID, (short) 0, (short)PCID.length);
        Util.arrayCopyNonAtomic(m_ramArray, (short)PCID.length, m_NoncePC, (short) 0, NONCELENGTH);
        
        if(compare == 0){
            //byte[] NonceCARD = JCSystem.makeTransientByteArray(NONCELENGTH, JCSystem.CLEAR_ON_DESELECT);
            m_secureRandom.generateData(m_NonceCARD, (short) 0, NONCELENGTH);
            
            byte[] replyAPDUPayload = JCSystem.makeTransientByteArray((short) (CARDID.length + (2*NONCELENGTH)) , JCSystem.CLEAR_ON_DESELECT);
            
            Util.arrayCopyNonAtomic(CARDID, (short) 0, replyAPDUPayload, (short) 0, (short)CARDID.length);
            Util.arrayCopyNonAtomic(m_ramArray, (short) PCID.length, replyAPDUPayload, (short)CARDID.length, NONCELENGTH);
            Util.arrayCopyNonAtomic(m_NonceCARD, (short) 0, replyAPDUPayload, (short) (CARDID.length + NONCELENGTH), (short)(m_NonceCARD.length));
            
            Encrypt(replyAPDUPayload, (short) 1);
            
            Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short)(replyAPDUPayload.length + IVLENGTH));
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (replyAPDUPayload.length + IVLENGTH));
            
            //Util.arrayCopyNonAtomic(replyAPDUPayload, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short)replyAPDUPayload.length);
            //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)replyAPDUPayload.length);
            
        }
        else{
            ISOException.throwIt(BAD_SESSION1);
        }
        
    }
    
    void acknowledgeSessionKey(APDU apdu) {
        
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        byte[] messageIV = JCSystem.makeTransientByteArray(dataLen, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, messageIV, (short) 0, dataLen);

        Decrypt(messageIV, (short) 1);
        
        //byte[] SessionKey = JCSystem.makeTransientByteArray(NONCELENGTH, JCSystem.CLEAR_ON_DESELECT);
        for (short i = 0; i < NONCELENGTH; i++) {
            SESSIONKEY[i] = (byte) (m_NoncePC[i] ^ m_NonceCARD[i]);
        }
        
        //Util.arrayCopyNonAtomic(m_NoncePC, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, NONCELENGTH);
        //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, NONCELENGTH);
        
        byte compare = Util.arrayCompare(m_ramArray, (short)0, SESSIONKEY, (short) 0, NONCELENGTH);
        
        if (compare == 0){
            m_aesKey.setKey(m_ramArray, (short) 0); 
        }else
            ISOException.throwIt(BAD_SESSION2);
    }
    
    byte[] generateHMAC(byte[] bufferIn) {
        
        byte[] apdubuf = bufferIn;
        short dataLen = (short) bufferIn.length;
       
        byte ipad = 0x36;
        byte opad = 0x5c;

        byte[] opadK = JCSystem.makeTransientByteArray(dataLen, JCSystem.CLEAR_ON_DESELECT);
        byte[] ipadK = JCSystem.makeTransientByteArray(dataLen, JCSystem.CLEAR_ON_DESELECT);

        byte[] arrayCat = JCSystem.makeTransientByteArray((short) (KEYLENGTH + dataLen), JCSystem.CLEAR_ON_DESELECT);
        byte[] arrayFinal = JCSystem.makeTransientByteArray(hashLength, JCSystem.CLEAR_ON_DESELECT);

        byte[] key = JCSystem.makeTransientByteArray(KEYLENGTH, JCSystem.CLEAR_ON_DESELECT);
        m_aesKey.getKey(key, (short) 0);

        for (short i = 0; i < KEYLENGTH; i++) {
            ipadK[i] = (byte) (key[i] ^ ipad);
            opadK[i] = (byte) (key[i] ^ opad);
        }

        byte[] tempArray = JCSystem.makeTransientByteArray((short) (KEYLENGTH + hashLength), JCSystem.CLEAR_ON_DESELECT);
        
        Util.arrayCopyNonAtomic(opadK, (short) 0, tempArray, (short) 0, KEYLENGTH);

        Util.arrayCopyNonAtomic(ipadK, (short) 0, arrayCat, (short) 0, KEYLENGTH);

        Util.arrayCopyNonAtomic(apdubuf, (short) 0, arrayCat, KEYLENGTH, dataLen);

        if (m_hash != null) {
            m_hash.doFinal(arrayCat, (short) 0, (short) (KEYLENGTH + dataLen), tempArray, KEYLENGTH);

        }

        if (m_hash != null) {
            m_hash.doFinal(tempArray, (short) 0, (short) (KEYLENGTH + hashLength), arrayFinal, (short) 0);
        }
        
        return (arrayFinal);
    }
    
    void getSecurePassword(APDU apdu) {
        
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        short inMessageLength = (short)(dataLen - hashLength - IVLENGTH);
        byte[] inHMAC = JCSystem.makeTransientByteArray(hashLength, JCSystem.CLEAR_ON_DESELECT);
        byte[] inMessageIV = JCSystem.makeTransientByteArray((short)(inMessageLength + IVLENGTH), JCSystem.CLEAR_ON_DESELECT);
        
        byte[] generatedHMAC = JCSystem.makeTransientByteArray(hashLength , JCSystem.CLEAR_ON_DESELECT);
        
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, inMessageIV, (short)0, (short)(inMessageLength + IVLENGTH));
        //Util.arrayCopyNonAtomic(apdubuf, (short)(ISO7816.OFFSET_CDATA + inMessageLength), inIV, (short)0, IVLENGTH);
        Util.arrayCopyNonAtomic(apdubuf, (short)(ISO7816.OFFSET_CDATA + inMessageLength + IVLENGTH), inHMAC, (short)0, hashLength );
        
        //Construct HMAC of Encr(MEssage) || IV
        generatedHMAC = generateHMAC(inMessageIV);
        
        byte compare = Util.arrayCompare(inHMAC, (short)0, generatedHMAC, (short) 0, hashLength);
        
        if (compare == 0){
            
            Decrypt(inMessageIV, (short) 3);
            byte[] receivedPIN = JCSystem.makeTransientByteArray(PINSize, JCSystem.CLEAR_ON_DESELECT);
            Util.arrayCopyNonAtomic(m_ramArray, (short)0, receivedPIN, (short)0, PINSize);
            
            if (m_pin.check(receivedPIN, (short) 0, (byte) PINSize) != false) {
                byte[] password = JCSystem.makeTransientByteArray(KEYLENGTH, JCSystem.CLEAR_ON_DESELECT);
                m_aesPassword.getKey(password, (short) 0);
                
                Encrypt(password, (short)3);
                
                Util.arrayCopyNonAtomic(m_ramArray, (short) 0, inMessageIV, (short) 0, (short)(KEYLENGTH + IVLENGTH));
                
                generatedHMAC = generateHMAC(inMessageIV);
                
                Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short)(KEYLENGTH + IVLENGTH));
                Util.arrayCopyNonAtomic(generatedHMAC, (short) 0, apdubuf, (short)(ISO7816.OFFSET_CDATA + KEYLENGTH + IVLENGTH), hashLength);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (KEYLENGTH + IVLENGTH + hashLength));
            } else {
                ISOException.throwIt(SW_BAD_PIN);
            }
        }
        else{
            apdu.setOutgoing();
            apdu.setOutgoingLength( (short) 2 );
            Util.setShort(apdubuf,(short)(0), (short)(13));
            apdu.sendBytes((short)0 , (short) 2);
        }       
    }

    /*
    void EncryptDecrypt(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        if ((dataLen % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
      
        byte[] encData = new byte[KeySize];
        byte status = m_aesKey.getKey(encData, (short) 0);
 
        m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT, apdubuf, (short)(ISO7816.OFFSET_CDATA + KeySize), (short)(dataLen-KeySize));
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, KeySize, m_ramArray, (short) 0);    

        // COPY DECRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, KeySize);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, KeySize);
    }*/

}

