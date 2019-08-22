This program was made possible by Crypto++ libraries. These can be found here: https://www.cryptopp.com/

This program does the following for encryption:
1. Collects all file names in the target directory
2. For all files:
	- Creates a unique AES key.
	- Encrypts the contents of the file using that AES key.
	- Encrypts all necessary decrypting AES data, namely the AES key (represented in hex), and iv (represented in hex), using a hard-coded public RSA key.
	- Stores the encrypted AES data as hex at the top of the file, with the cipherText of the file's previous contents beneath.

This program does the following for decryption:
1. Collects all file names in the target directory
2. For all files:
	- Takes the encrypted AES data from the top of the file and decrypts it using a hard-coded private RSA key.
	- Uses the decrypted AES data to decrypt the cipherText stored in the same file.
	- Clears the contents of the file, and writes the decrypted cipherText back in

Supported AES key sizes:
	128
	192
	256

Supported RSA key sizes:
	1024
	2048
	3072

To encrypt:
1. Go to the bin directory
2. Enter the following command:
   ./cppAES e <AES key size> <RSA key size> /path/from/root/to/target/dir
Notice:
* e is for encrypt
* You want to start the path from /

Also, the /encryptFiles directory is already setup to be encrypted. The ./setupEncryptedFiles.sh script will rebuild it if it breaks

To decrypt:
1. Go to the bin directory
2. Enter one of the following commands:
   ./cppAES d <AES key size> <RSA key size> /path/from/root/to/target/dir
Notice:
* d is for decrypt
* Once again, start the path from /
