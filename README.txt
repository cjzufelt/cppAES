This program does the following for encryption:
1. Collects all file names in the target directory
2. For all files:
	- Creates a unique AES key.
	- Encrypts the contents of the file using that AES key.
	- Encrypts all necessary decrypting data, namely the file name, AES key (represented in hex), and iv (represented in hex), using a hard-coded public RSA key.
	- Stores the encrypted data as hex in the keyfile ".AESKeys.txt" found in the target directory. Every entry to the keyfile is ended with a newline.

This program does the following for decryption:
1. Opens the keyfile ".AESKeys.txt"
2. For every entry (line) in the keyfile:
	- Turns the entry from hex to a string
	- Decrypts the string using a hard-coded private RSA key
	- Turns the AES key and iv from hex back into their usable form
	- Decrypts the file with its associated AES key and iv
3. Deletes the keyfile
	
	

To encrypt:
1. Go to the bin directory
2. Enter one of the following commands:
   ./c++aes e 128 /path/from/root/to/target/dir
   ./c++aes e 192 /path/from/root/to/target/dir
   ./c++aes e 256 /path/from/root/to/target/dir
Notice:
* e is for encrypt
* The number following e determines the keysize in bits
* You want to start the path from /

Also, the /encryptFiles directory is already setup to be encrypted. The ./makeFiles.sh script will rebuild it if it breaks
A file named .AESKeys.txt will be created in the target directory when encrypting. It is deleted when decrypting. It has the format:
path[tab]key[tab]iv\n


To decrypt:
1. Go to the bin directory
2. Enter one of the following commands:
   ./c++aes d 128 /path/from/root/to/target/dir
   ./c++aes d 192 /path/from/root/to/target/dir
   ./c++aes d 256 /path/from/root/to/target/dir
Notice:
* d is for decrypt
* The number following d must match the keysize you encrypted with
* Once again, start the path from /

Remember, decrypting will delete the .AESKeys.txt file
