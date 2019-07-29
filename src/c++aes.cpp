/*
g++ -g c++aes.cpp -I /usr/local/include/cryptopp/ /usr/local/lib/libcryptopp.a -o ../bin/c++aes
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <dirent.h>
#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "files.h"
#include "cryptlib.h"
#include "files.h"
#include "hex.h"
#include "osrng.h"

using namespace CryptoPP;
using std::string;
using std::fstream;
using std::vector;
using std::cout;
using std::endl;
using std::istreambuf_iterator;
using std::ios_base;
using std::remove;
using std::ios;
using std::invalid_argument;

unsigned short KEYLENGTH;

void encrypt(const string& dirPath);
vector<string> getFilePaths(const string& dirPath);
string encryptContents(const string& filePath, const string& contents);
void storeAndPrintKey(const string& filePath, const SecByteBlock& key, const SecByteBlock& iv);

void decrypt(const string& dirPath);
void parseAndPrintLine(const string& fileContents, string& filePath, string& keyString, string& ivString);
string decryptContents(const string& contents, const SecByteBlock& key, const SecByteBlock& iv);

string stringToHex(const string& input);
string hexToString(const string& input);
string readFileContents(const string& filePath);
void writeAlteredContents(const string& filePath, const string& cipherText);


/**
 * This function is effectively the main for encryption.
 * It uses getFilePaths to get all the file names in the directory, then iterates through all 
 * those files and calls all the functions vital to the encryption of the file
 */
void encrypt(const string& dirPath) {
    // Initializes vector with all file names and the file object that will be reading them
    vector<string> filePaths;
    filePaths = getFilePaths(dirPath);

    // Iterates through file names and opens and encrypts them one by one
    for (int i = 0; i < filePaths.size(); ++i) {
        string contents;
        contents = readFileContents(filePaths.at(i));

        // Encrypts the contents of the file and stores it in the string cipherText
        string cipherText;
        cipherText = encryptContents(filePaths.at(i), contents);

        writeAlteredContents(filePaths.at(i), cipherText);
    }
}


/**
 * Opens the given directory and writes all the file names in that directory into a vector for
 * later use. Notice, it does not read in the current directory (.), the previous directory (..),
 * or the key file (.AESKeys.txt)
 */
vector<string> getFilePaths(const string& dirPath) {
    DIR* dir;
    dirent* pdir;
    vector<string> files;

    dir = opendir(dirPath.c_str());

    // Reads everything in the directory and puts the names in a vector, excluding '.' and '..'
    while (pdir = readdir(dir)) {
        if ((string)pdir->d_name != "." && (string)pdir->d_name != ".." && (string)pdir->d_name != ".AESKeys.txt") {
            files.push_back(dirPath + pdir->d_name);
        }
    }

    return files;
}


/**
 * Takes the contents of the file stored in the string 'contents', encrypts those contents, and stores them in the
 * string 'cipherText'. Does not return a value, but rather alters cipherText directly as a pass-by-reference.
 */
string encryptContents(const string& filePath, const string& contents) {
    AutoSeededRandomPool rnd;
    string cipherText;

    // Generate a random key
    SecByteBlock key(0x00, KEYLENGTH);
    rnd.GenerateBlock(key, key.size());

    // Generate a random IV
    SecByteBlock iv(AES::BLOCKSIZE);
    rnd.GenerateBlock(iv, iv.size());

    // Create Cipher Text
    CryptoPP::AES::Encryption aesEncryption(key, KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText));  //FileSink
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(contents.c_str()), contents.length());
    stfEncryptor.MessageEnd();

    // Change key into string so that it can be written to the key file
    storeAndPrintKey(filePath, key, iv);

    return cipherText;
}


/**
 * Takes the filePath of the file it just encrypted and the key that encrypted it and stores them together in the file
 * ".AESKeys.txt"
 * The key has to be turned into a string in order to be stored
 */
void storeAndPrintKey(const string& filePath, const SecByteBlock& key, const SecByteBlock& iv) {
    // Turn the key and iv into strings
    string keyString(reinterpret_cast<const char*>(key.data()), key.size());
    string ivString(reinterpret_cast<const char*>(iv.data()), iv.size());
    string keyHex = stringToHex(keyString);
    string ivHex = stringToHex(ivString);

    // Store the key and the dirPath to the file it just encrypted together in ".AESKeys.txt"
    fstream file;
    string keyFilePath = filePath.substr(0, filePath.find_last_of("/") + 1) + ".AESKeys.txt";
    file.open(keyFilePath, fstream::out | ios_base::app | ios::binary);
    file << filePath << "\t" << keyHex << "\t" << ivHex << endl;
    file.close();

    // Output what was just written to the .AESKeys.txt file to the terminal
    cout << "WRITING:" << endl;
    cout << filePath << endl;
    cout << "key: " << keyHex << "\t" << keyString.length() << endl;
    cout << "iv: " << ivHex << "\t" << ivString.length() << endl << endl;
}


/**
 * This function is effectively the main for decryption.
 * It uses the .AESKeys.txt file to find all the encrypted file names in the directory, then
 * iterates through all those files and calls all the functions vital to the decryption of the file
 */
void decrypt(const string& dirPath) {
    fstream keyFile;
    string keyPath = dirPath + ".AESKeys.txt";
    keyFile.open(keyPath, fstream::in | ios::binary);

    string fileContents;
    while (getline(keyFile, fileContents)) {
        string filePath;
        string keyString;
        string ivString;

        parseAndPrintLine(fileContents, filePath, keyString, ivString);

        fileContents.clear();

        // Turns the keyString and ivString back into usable keys
        SecByteBlock key((const byte*)keyString.data(), keyString.size());
        SecByteBlock iv((const byte*)ivString.data(), ivString.size());

        // Stores all file contents in the string 'contents'
        string contents;
        contents = readFileContents(filePath);

        // Decrypts contents and stores them in plaintext
        string plainText = decryptContents(contents, key, iv);

        writeAlteredContents(filePath, plainText);
    }

    // Close the file from reading, then open it again and clear it, then delete the file entirely
    // The redundancy of clearing and deleting the file should ensure no data is ever left behind
    keyFile.close();
    keyFile.open(keyPath, fstream::out | fstream::trunc | ios::binary);
    keyFile.close();
    if (remove(keyPath.c_str())) {
        cout << endl << "Could not delete keyfile" << endl << endl;
    }
}


/**
* Takes a line of the .AESKeys.txt file and segments out the filePath, keyString, and ivString
* It stores them in string variables and prints out their values in hex to the terminal
*/
void parseAndPrintLine(const string& fileContents, string& filePath, string& keyString, string& ivString) {
    unsigned int pathEndIndex = fileContents.find("\t");
    filePath = fileContents.substr(0, pathEndIndex);

    // I multiply KEYLENGTH and BLOCKSIZE by 2 because each hex digit is a nibble, not a byte
    string keyHex = fileContents.substr(pathEndIndex + 1, KEYLENGTH * 2);
    string ivHex = fileContents.substr(fileContents.length() - AES::BLOCKSIZE * 2);
    keyString = hexToString(keyHex);
    ivString = hexToString(ivHex);

    // Output what was just read from the AESKeys.txt file to the terminal
    cout << "READING:" << endl;
    cout << filePath << endl;
    cout << "key: " << keyHex << "\t" << keyString.length() << endl;
    cout << "iv: " << ivHex << "\t" << ivString.length() << endl << endl;
}

/**
 * Uses the library and the stored key and iv to decrypt the encrypted contents of a file
 */
string decryptContents(const string& contents, const SecByteBlock& key, const SecByteBlock& iv) {
    string plainText;

    CryptoPP::AES::Decryption aesDecryption(key, KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(plainText));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(contents.c_str()), contents.length());
    stfDecryptor.MessageEnd();

    return plainText;
}


/**
 * Converts the given string to hex and returns it
 */
string stringToHex(const string& input) {
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i) {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}


/**
 * Converts the given hex to a string and returns it
 */
string hexToString(const string& input) {
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) throw std::invalid_argument("not a hex digit");

        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) throw std::invalid_argument("not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}


/**
 * Opens the file at the given filePath and reads in the contents, then returns them
 */
string readFileContents(const string& filePath) {
    fstream file;

    file.open(filePath, fstream::in | ios::binary);
    string contents((istreambuf_iterator<char>(file)), (istreambuf_iterator<char>()));
    file.close();

    return contents;
}


/**
 * Opens and clears the file at the given filePath, writes in the given cipherText, 
 * and closes it.
 */
void writeAlteredContents(const string& filePath, const string& alteredContents) {
    fstream file;

    // Opens the file, clears all data inside, writes cipherText, and closes it
    file.open(filePath, fstream::out | fstream::trunc | ios::binary);
    file << alteredContents;
    file.close();
}


int main(int argc, char* argv[]) {
    if (argc != 4) {
        cout << endl << "First argument should be:" << endl;
        cout << "e" << "\t" << "Encrypt" << endl;
        cout << "d" << "\t" << "Decrypt" << endl << endl;
        cout << "Second argument should be:" << endl;
        cout << "128" << "\t" << "128-bit key" << endl;
        cout << "192" << "\t" << "192-bit key" << endl;
        cout << "256" << "\t" << "256-bit key" << endl << endl;
        cout << "Third argument should be the path to the target directory" << endl << endl;
        return 1;
    }

    // Checks to make sure the dirPath ends with a '/' so that the file names can be appended
    string dirPath = argv[3];
    if (dirPath[dirPath.length() - 1] != '/') {
        dirPath += "/";
    }

    switch (atoi(argv[2])) {
    case 128:
        KEYLENGTH = 16;
        break;
    
    case 192:
        KEYLENGTH = 24;
        break;

    case 256:
        KEYLENGTH = 32;
        break;

    default:
        cout << "Second argument should be:" << endl;
        cout << "128" << "\t" << "128-bit key" << endl;
        cout << "192" << "\t" << "192-bit key" << endl;
        cout << "256" << "\t" << "256-bit key" << endl;
        break;
    }


    // Checks to ensure that the user has specified whether they want to encrypt or decrypt,
    // Else it tells them to do so
    if ((string)argv[1] == "e") {
        encrypt(dirPath);
    }
    else if ((string)argv[1] == "d") {
        decrypt(dirPath);
    }
    else {
        cout << "First argument should be:" << endl;
        cout << "e" << "\t" << "Encrypt" << endl;
        cout << "d" << "\t" << "Decrypt" << endl;
        return 1;
    }

    return 0;
}