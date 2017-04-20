/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */
package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SimpleApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET                = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_ENCRYPT                    = (byte) 0x50;
    final static byte INS_DECRYPT                    = (byte) 0x51;
    final static byte INS_SETKEY                     = (byte) 0x52;
    
    final static byte INS_GETKEY                     = (byte) 0x53;
    final static byte INS_RANDOM                     = (byte) 0x54;
    final static byte INS_VERIFYPIN                  = (byte) 0x55;
    final static byte INS_SETPIN                     = (byte) 0x56;
    final static byte INS_RETURNDATA                 = (byte) 0x57;
    final static byte INS_SIGNDATA                   = (byte) 0x58;
    final static byte INS_GETAPDUBUFF                = (byte) 0x59;
    final static byte INS_ENCRYPTDECRYPT             = (byte) 0x5B;
    
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

    private   AESKey         m_aesKey = null;
    private   RandomData     m_secureRandom = null;
    private   MessageDigest  m_hash = null;
    private   OwnerPIN       m_pin = null;
    private   Cipher         m_encryptCipher = null;
    private   Cipher         m_decryptCipher = null;

    // TEMPORARRY ARRAY IN RAM
    private   byte        m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte       m_dataArray[] = null;

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

            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            
            // CREATE RANDOM DATA GENERATORS
             m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            // SET KEY VALUE
            m_aesKey.setKey(m_dataArray, (short) 0);
            
            // INIT CIPHERS WITH NEW KEY like a default key
            m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);

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
                case INS_SETKEY: SetKey(apdu); break;
                case INS_GETKEY: GetKey(apdu); break;
                case INS_VERIFYPIN: VerifyPIN(apdu); break;
                case INS_SETPIN: SetPIN(apdu); break;
                case INS_ENCRYPTDECRYPT: EncryptDecrypt(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    // SET ENCRYPTION & DECRYPTION KEY
    void SetKey(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();
      
      if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_128) ISOException.throwIt(SW_KEY_LENGTH_BAD);

      m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA);
      
      // INIT CIPHERS WITH NEW KEY
      //m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
      //m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);

    }
    
    void GetKey(APDU apdu){
        byte[] apdubuf = apdu.getBuffer();
        short  dataLen = apdu.setIncomingAndReceive();
        
        byte[] temp = new byte[KeySize];
                
        byte status = m_aesKey.getKey(temp, (short) 0);
        
        Util.arrayCopyNonAtomic(temp, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) temp.length);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) temp.length);
    }

    // VERIFY PIN
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
    
    void HMAC(APDU apdu) {
        
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
       
        byte ipad = 0x36;
        byte opad = 0x5c;

        byte[] opadK = JCSystem.makeTransientByteArray(dataLen, JCSystem.CLEAR_ON_DESELECT);
        byte[] ipadK = JCSystem.makeTransientByteArray(dataLen, JCSystem.CLEAR_ON_DESELECT);

        byte[] arrayCat = JCSystem.makeTransientByteArray((short) (2 * dataLen), JCSystem.CLEAR_ON_DESELECT);
        byte[] arrayFinal = JCSystem.makeTransientByteArray((short) (2 * dataLen), JCSystem.CLEAR_ON_DESELECT);

        byte[] key = JCSystem.makeTransientByteArray(dataLen, JCSystem.CLEAR_ON_DESELECT);
        m_aesKey.getKey(key, (short) 0);
        //m_aesKey.getKey(key, (short) 0);

        for (short i = 0; i < dataLen; i++) {
            ipadK[i] = (byte) (key[i] ^ ipad);
            opadK[i] = (byte) (key[i] ^ opad);
        }

        Util.arrayCopyNonAtomic(opadK, (short) 0, m_ramArray, (short) 0, dataLen);
        // System.out.println("Y = K XOR OPAD " + CardMngr.bytesToHex(m_ramArray));

        Util.arrayCopyNonAtomic(ipadK, (short) 0, arrayCat, (short) 0, dataLen);
        // System.out.println("K XOR IPAD " + CardMngr.bytesToHex(arrayCat));

        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, arrayCat, dataLen, dataLen);
        // System.out.println("(K XOR IPAD) ||C " + CardMngr.bytesToHex(arrayCat));

        if (m_hash != null) {
            m_hash.doFinal(arrayCat, (short) 0, (short) ((short) 2 * dataLen), m_ramArray, dataLen);
            //System.out.println("Y||X = (K XOR OPAD) || X : " + CardMngr.bytesToHex(m_ramArray));

        }

        if (m_hash != null) {
            m_hash.doFinal(m_ramArray, (short) 0, (short) (dataLen + (short) 20), arrayFinal, (short) 0);
        }

        //Util.arrayCopyNonAtomic(HOTP, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, OTPsize);

        //apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, OTPsize);
    }

    
    void EncryptDecrypt(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        if ((dataLen % 16) != 0) ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
      
        byte[] encData = new byte[KeySize];
        byte status = m_aesKey.getKey(encData, (short) 0);

        //byte[] receivedIV = new byte[KeySize];
        
        //Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, encData, (short) 0, KeySize);
        
        //Util.arrayCopyNonAtomic(apdubuf, (short)(ISO7816.OFFSET_CDATA + KeySize), m_ramArray , (short) 0, (short)(dataLen - KeySize));
      
        m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT, apdubuf, (short)(ISO7816.OFFSET_CDATA + KeySize), (short)(dataLen-KeySize));
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, KeySize, m_ramArray, (short) 0);    

        // COPY DECRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, KeySize);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, KeySize);
    }

}

