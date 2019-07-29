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
