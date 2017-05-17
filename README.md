# pv204 Project - Modification of open source Java project for file encryption to use smartcard (JavaCard) as HSM 

# 1.  This project seeks to modify existing file Encryption Program AESCrypt written in Java to use a Javacard to supply secret password , which is otherwise taken from user as a terminal input.

# 2. The project is written in three source files inside the src directory in two folders which are named as simpleapplet ( for the javacard sde program) and the other folder is simpleapdu.

# e.3. The simpleapplet has only one java src file to be compiled and uploaded in javacard uaing ant and gp tool.

# 4.   The SimpleApdu folder has source java files for compiling and running at PC end. The origininal AEScrypt file is included in the folder as it is with removal of main function, and functions for filr encryption decryption are used from this source in SimpleAPDUpdu.java file.

# 5.  The program has two components one each for setting up javacard appropriately in a trusted environment. All activities of setting up of user PIN and AEScrypt applucation password is undertaken through this trusted.java src file. 

# 6.  The SimpleAPDU.java is the other main program source used in operation for encryption and decryption of files using multilayered security features, described in brief below:

(A) Key negotiation and session key establishment using symmetric long term key which was created in trusted environment.

(B) setting up of a secure channel after mutual PCId and JavaCardId auhentication and also PiN verification by the JavaCard.

(C) Enablung/ creation of HMAC based integrity for all subsequent transactions in the channel.

(D) Request and retrival of Applucation encryption and decryption password from the card using PIN authentication in an secure encrypted channel with HMAC integrity.
