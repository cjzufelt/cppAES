/*
g++ -g cppAES.cpp -I /usr/local/include/cryptopp/ /usr/local/lib/libcryptopp.a -o ../bin/cppAES

break TF_EncryptorBase::Encrypt
break pubkey.cpp:165

break CryptoPP::PKCS_EncryptionPaddingScheme::Pad

break CryptoPP::OAEP_Base::Pad
break CryptoPP::OAEP_Base::Unpad
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <dirent.h>
#include <unistd.h>
#include "modes.h"
#include "aes.h"
#include "rsa.h"
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

string DIRPATH;
unsigned short KEYLENGTH;
string PUBLIC_KEY_HEX;
string PRIVATE_KEY_HEX;

const string PUBLIC_KEY_HEX_1024 = 
    "30819D300D06092A864886F70D010101050003818B0030818702818100F443170C0FAD9519FC1855685DE0A0D88BDE211D4CCA92263156C3F87647A79EACCE7CDA16765C0FC56A847BBC681A2DF3DF53FABFB0B79DF419B08A8E3DE8EED22507199665C0009E61E5D831C9FEA9C74724AAC724FEEA2E97F153866E9FB09681417D9C171B0F8779564AA5BA25543E0D6C8ABF1987FF02F2E22D504AFA47020111";
const string PRIVATE_KEY_HEX_1024 = 
    "30820275020100300D06092A864886F70D01010105000482025F3082025B02010002818100F443170C0FAD9519FC1855685DE0A0D88BDE211D4CCA92263156C3F87647A79EACCE7CDA16765C0FC56A847BBC681A2DF3DF53FABFB0B79DF419B08A8E3DE8EED22507199665C0009E61E5D831C9FEA9C74724AAC724FEEA2E97F153866E9FB09681417D9C171B0F8779564AA5BA25543E0D6C8ABF1987FF02F2E22D504AFA470201110281806BC33EDFAC90585E499243CC296AA15079F10E9BFC3B407A42F192B1615BD9023D2DEBC9A07F82F7E62776AF0F5B1A9BCD791D8536739C4D36FC465B3EC0F5D1E975AAA771D8AB36395C2DC7CE7306F20815FCDC8FF0893FB762EE0826292ED830D748AF3989284FE9FE3D05276E58D149E7F8831F1E33ADC77516DA1BB90E99024100FD71A105925AEEEF56BC03BBFBF4C6D44C8D4D65F7172B8B40CE6C1B9EDDE883D39E2B927FF86184E8B4B97702B340335F0A96F58371342E2672601368B7E72F024100F6B9C12101FD914109E602DFD95905F524219A1DABEC9C45F8C72569B3335E0F8761823BCCE7D5A2481DF0618DEAA4578CD2E68E2852CD9C4B993D3C97AB5869024100D0B7EE0496A53D3D92B8F40438E7B2CCF3BFA926CB7C7E36719AEF9E4698A15D8118D896C3BD7D7C8367A7CB6BA2AD577B7221F75D300CDAB64012E2CEB591350241009FA55ED91F67D67560C201DC23399A7171BB63B8D8A828E1FB53AECBEC6C88282A6C4535C0D23EF08904503F1F97D3C02DF1E07A1A1775FBB87236AEBC7DEDE9024054C6AFEDCAE459F18E76A61A28C2D480CB7C082DECACE4402B924A9FE6E15AEC76C5FB87FFED760ED8E173B7A5812A7A016E435EA22AC17540AC830D9C8D9E58";

const string PUBLIC_KEY_HEX_2048 = 
    "30820120300D06092A864886F70D01010105000382010D00308201080282010100B36E8C5C38AEEFD2D2C15241CE6F8695406D38BB4E35DBFD5B0C075616783CE9823E88FA0E515039C6C963EAFDCF6030613B01FFEB7B417B990C417ED48F80815CA4B96713F660024FDFE0674FAD2A8469EE74B6FCA10CC2FC7A19A930A313B542B58DD7A7E8062369253E01153FC076085A9C0A9F34D9718A1A09B3786449DA56AE842730976A26F04ECD5C6D86A10A3D99488585B4836CB5BF6EB37A76FAD0010EBC7FF739B1E7B576D88D43DDF7C08F0BBF9F091CA65A4D1F707BEDCB714FFB10AC16E286CC5546A036C2ECC2B8C9C1585C4427032A024C7E73399A388AEFADDCA83FF9C1EFF57C3BBE59D1D2892C1B5A4B5FC2188F632E6776BBB42F7085020111";
const string PRIVATE_KEY_HEX_2048 = 
    "308204BC020100300D06092A864886F70D0101010500048204A6308204A20201000282010100B36E8C5C38AEEFD2D2C15241CE6F8695406D38BB4E35DBFD5B0C075616783CE9823E88FA0E515039C6C963EAFDCF6030613B01FFEB7B417B990C417ED48F80815CA4B96713F660024FDFE0674FAD2A8469EE74B6FCA10CC2FC7A19A930A313B542B58DD7A7E8062369253E01153FC076085A9C0A9F34D9718A1A09B3786449DA56AE842730976A26F04ECD5C6D86A10A3D99488585B4836CB5BF6EB37A76FAD0010EBC7FF739B1E7B576D88D43DDF7C08F0BBF9F091CA65A4D1F707BEDCB714FFB10AC16E286CC5546A036C2ECC2B8C9C1585C4427032A024C7E73399A388AEFADDCA83FF9C1EFF57C3BBE59D1D2892C1B5A4B5FC2188F632E6776BBB42F7085020111028201002A382106A3ECED228BF14087F4567A050019B2FEE539D968CA20F2AAD81C4A914BD27A95308B9A67F289BD283BB852DE34FED34B46775AB3AB8A69C37D4EF10F6117B3274FFDBC3CC77FF890C7740A0109DDC11BFF34F3F1A4D16F731A80B957D3760341CD2788F945EAA52D6E695A76201551E461B2150BA806206676AE2F7E455732E739DE19AA0C724725657E18C43F17BF5860AF5D7C4D85600C1384E2EC8B7FE65A9BC31843C7014A942351DB7838B3FEA03C3EE49740C288281DFF1241CD40F2DEF65DDF7BAC7E72654AFD7275AA1DC7B012DCB0754F01DC5A19565279E66E38A7B82DDB4A2B312B949E261937C305772A0E7D57B95903CA29D6603DA102818100BD32420A4186254552BEF58BE5EB6D0B0406938B17BE711645713D9B581CE8E022601A4E7C77A057C029550FCD60F5F78AA2BA8621649E5DC38DF06A96D2040B0741EEA8CDE4DD452E5B48C858D75AD4A23B9C5D26C4F3739F8190846E9D292898E6458163FE13E9D96C962BE0EBEAB4C53EC15AD21979402E2BBD35FCF9FDB302818100F2C9A9C6392157CEE8AA297198434ABD2D6DC7C2D30CC50626D758E4CF654D828DCF0F3064C4EA6FE7880687E0611D0A136C0AEFE7ACBC79B656BD66D77D5FAD4B7AB53A7D92F9427B2B87CC153637810C1E2F3AB014489C1D34FA363FEC834101A1F1F5C700F8106B3E2EF650C4B34A59444F92326A614F45EB9E53E81C6CE70281802C844BC62D88F9B5F55A1BA872558311A69822B750E184053D840E7EE78E54E97180063095C1CB5FF0FAAA9A4E712AD0D553772E9E7207251EF438918CE61F11A75ACEBE4E903410472489988D5FD922F8FEF79D7288B1C0DA3C9A79837045EB6F453D87DB4AD7825146B9EC34EC373997D287D9226058C3CEA0E139E12BC33902818100E48190BA901F61B3ADCD542EAD6C8293EE8570B75D3931E7AC15F94FD24139E4493B5996F56E09D2BBCB5170D32E3972E51A64A58EC0B1637E6FC151BBC14AFD74374127FDB7812F82FBCB1A6E51252E2985D2191E313547A304AF421E0BC6D3C54D1FF660F1DA69CE58A4AB974FB7CD81313BD4E427E31D6EFBE04EF893395102818100BB4194480049162EC344B9FEA45DA6E9FFEB8A365EDEF027D0408C72C334C81F06AF1BE9EC881C43C7B84B755632BB5315B6B52B86190C406618A2313E3E1981BA3855683819DEB3172471C7154CC02473F998B78594868E50A6C44D3F24C539913C6E9182BAE40A1AA2DEE2787D9CF3ABC7FDBD336E889B56139B3F49868A11";

const string PUBLIC_KEY_HEX_3072 =
    "308201A0300D06092A864886F70D01010105000382018D00308201880282018100AA8EC7C15039990854ADC8B8ACB929B4BA06C5A67198400DEBD8904AE9045EB4ECCAAE609140029CE2DA803D7A1878378A6BCE72A1E224C9EBB317B477BDB8B95B41E6DAC1CBFE881B18E44C4A88C9D9DFCD348880C05F0A218B1B0E244E0D37E5A3883B353732BDDCE107A3B6B6B409A781145A58277BCB832E302ADC9F3A44F865A8E3953E2F82CC1CA4C272FC7797CCA0A098AD8D18734134E93953999B8B78B19DF55B42275FF7D5E212971BDE566D617EBB67335902179ED8F4B0EDC1095DE38A1BEE1BE3C685FD24B03F3A160824993B2E0CF8EF2DDCBB203A63FE0FB666D52B850E881B192298D56975A9CD0EFF3CADF5C9CA7849BCF62B448C66F2467F1E4E319C95F11BD08F765C942761D97F7955DAE8C3CE117E55B34B54A70AB14E8903993EF790EA3C19AB0DD03ECEBDA2E5E03C354AF6B4569E349AF962D00AA488E50481E267020B96630A65F992934932675E63878FD6F67D465E4ADBB3B016B4DDED70323FC6DB73AADDE3F7BBB76DEC234A2037661277A9EFF885BA26F1020111";
const string PRIVATE_KEY_HEX_3072 =
    "308206FB020100300D06092A864886F70D0101010500048206E5308206E10201000282018100AA8EC7C15039990854ADC8B8ACB929B4BA06C5A67198400DEBD8904AE9045EB4ECCAAE609140029CE2DA803D7A1878378A6BCE72A1E224C9EBB317B477BDB8B95B41E6DAC1CBFE881B18E44C4A88C9D9DFCD348880C05F0A218B1B0E244E0D37E5A3883B353732BDDCE107A3B6B6B409A781145A58277BCB832E302ADC9F3A44F865A8E3953E2F82CC1CA4C272FC7797CCA0A098AD8D18734134E93953999B8B78B19DF55B42275FF7D5E212971BDE566D617EBB67335902179ED8F4B0EDC1095DE38A1BEE1BE3C685FD24B03F3A160824993B2E0CF8EF2DDCBB203A63FE0FB666D52B850E881B192298D56975A9CD0EFF3CADF5C9CA7849BCF62B448C66F2467F1E4E319C95F11BD08F765C942761D97F7955DAE8C3CE117E55B34B54A70AB14E8903993EF790EA3C19AB0DD03ECEBDA2E5E03C354AF6B4569E349AF962D00AA488E50481E267020B96630A65F992934932675E63878FD6F67D465E4ADBB3B016B4DDED70323FC6DB73AADDE3F7BBB76DEC234A2037661277A9EFF885BA26F10201110282018003229FE8426A7875CCD9C86546F09488072F2EED699E17C40546CDF25175BA36263C3243A8512D3978E0407999C618CC50A982DA93EABECB3DBE961533246DBFA480452F50BD2962807F843257F55688B5FF10F737129855D5528E9D6FB9E7C5BBC02EBD52DC4F0CE6E24114E44CC5311E5F8C9C0380B9CE180EF779422C56B7DB27840BB682159449662C70C03B3AAB42D202F3BF6CF254F132DAE01CD4B4BDDBA161F66480465EF0CA8518CFF446E91E3EF7FA087C3CEE27F6AF4843409B13E81E7C07384AAC07B2A8A30C156C4A54A5FB7D65D3B348BDC15611501762178ED133250E3C71A09C20221B7A9D72A56E7EA828F2C121D34057E438364C3FB4EB77E071004EF7524761017A59E71008E93375DCAB00010B0E4E7E85457D38AA62C24F62CC2F855443C6512E372D4D25B5D588DE89060A908A48D670B5637B53A00DA561AB3ABB7DDACBFBF9C2BB59296255DB1CF6213FBF13F3BFA848EF984230AD8B9838A595F5DDE90974B10978404A362E9250824B063B70FF8E0602D6EAF10281C100BC29793335B1E62823ED1A4A99C434EC4F284BE92C5642AD2CB4237E75E4FCC346821F7F39B69FD5804712FD680E1AE5C5237D75C85689311F25889071D11337A0463E020D041FDAE93F2C7808A539ED498743DBF6E9E20C7A43FF01A60A9C96E1FAD44EF8C4E282DFD84ABC677142E6342266E0A4944FD0277A701A59228D83BECD69C16DE49FC3EE400884CB69567CA2B71618FCE51D1D440D56B43C2561B3041D5FEEE3B715A105B7C74D4543E69D27C1878CA4F891BD9B07EA32682D8E010281C100E80C8293288BD59537D3CB077E72E25229997CD4B0F0042E00F01BB6F60DAB004574C5CC2FDF5A1667DF1EC4320BBDE1832A1683C3DD716C56EB172A4D0C39D23259A6852E36BBAF7D6649FD0B4D0FF7ACE660DBBE6DF8FABC622F1F1291D2B7887C63E693772CCD37CDF497C868BB9A0E7A95D714DE564E4E5F045B7C71B083FF6386E0328CA2592AFE1457646AA3FE018529C4BC49D815E682935D8B28413E9820BEC1C303B7CAB6ECB12501F2F8885C451DD4FE80B4800CBA3E18B64778F10281C1008FE37ACCCEB537881B79141AEE0E82D2D31ED0A34005BA846D7AB1BB0EDC48D1904563614A405C1BBC72960D1356149196C0C95A11AB9616813AD1D7DE90D275D4EA6BA73721458948F412F260F6D1F1B0B2BB6BF90D3463E506D21051CBE1281638480027A59E27D85A1B088B569C91EBA1D63350ADA672001255B9CBB102CE287EF684DB90B668A721E8658C7DBA9B8B7CF2C7D072F82570466F7AC4950E79D5F8586B62D74CC66DC8C5957133EC964B93FE3E60096063D0E7EF53B913C6F10281C028F32619F818AD3873437E2E7FB9EBB425757061C4DF0FCBE20C41204989F1000C41C88D71DC1EF4E5275FC84511218226349A8FB92714040F56A9BC2BB6DD06F9D395DB44640300D9E4DFE15C58E4B33CA12026C74095596C89CC148ACE707ABDBB9928B09C8F6F82518584326CD5CFE46FFC5321CCE20DD1984C10250501083C209F54BDA058E28F1DC75AB75E1CF096DB439B30494440199E9279EB6174ECEDAB6CF5044BF341E40BA6CA4BA3590901395F9E0ECB6B25A7E4A18BE3EE7EC10281C05F54F60EA447D90A4A631AC3900EBE908EA3B696E239C95206369DF3B2B45D8CEDD796E35259D4E9BB995CB3BCFD2571C244B50873E1DC61D87F18E6B63DBA88FD7DE9F9C26E046AA83985BFC216D42B9F799724D941005D97713BD7DAE5187475311F2947262303A96D7930CCEC13D89865F4748BDF9BE426B91D4251EF7D712770FB5AA9D27891A25C72C97A4B378F3B17B53BE0A2884DC9469551109B496140BF9675204E4CF7FFEDE675CF863CFB36E233E27A1ED1BC221FCA84A98C89C7";

const string AES_KEY_HEX = "0F5D4C66B7839F9B68545A3E28CF96B1FDE626A2872E66B6B3FB61FEC4C38B2E";
const string AES_IV_HEX = "E716439B2C7262D90FED5E0D9A5A8B87";

// Encrypting functions
void aesEncrypt();
string aesEncryptContents(const SecByteBlock& key, const SecByteBlock& iv, const string& contents);
string rsaEncrypt(const string& input);
string stringToHex(const string& input);

// Decrypting functions
void aesDecrypt();
string rsaDecrypt(const string& input);
string aesDecryptContents(const string& contents, const SecByteBlock& key, const SecByteBlock& iv);
string hexToString(const string& input);

// General-purpose functions
vector<string> getFileNames();
string readfileContents(const string& filePath);
void writeAlteredContents(const string& filePath, const string& alteredContents);


/**
 * This function is effectively the main for encryption.
 * It uses getFileNames to get all the file names in the directory, then iterates through all 
 * those files and calls all the functions vital to the encryption of the file and AES data
 */
void aesEncrypt() {
    // Initializes vector with all file names and the file object that will be reading them
    vector<string> fileNames = getFileNames();

    // Iterates through file names and opens and encrypts them one by one
    for (int i = 0; i < fileNames.size(); ++i) {
        string contents = readfileContents(DIRPATH + fileNames.at(i));

        // Generates a unique AES key and iv, then uses them to encrypt the contents of the file
        AutoSeededRandomPool rnd;

        // Code that generates unique AES keys and ivs
        SecByteBlock key(0x00, KEYLENGTH);
        SecByteBlock iv(AES::BLOCKSIZE);
        rnd.GenerateBlock(key, key.size());
        rnd.GenerateBlock(iv, iv.size());

        // Encrypt the file contents
        string cipherText = aesEncryptContents(key, iv, contents);

        // Turn keys into easily storable and printable strings
        string aesKeyString(string(reinterpret_cast<const char*>(key.data()), key.size()));
        string aesIVString(string(reinterpret_cast<const char*>(iv.data()), iv.size()));

        // Concatenate the key and the iv for RSA encryption
        string aesData = aesKeyString + aesIVString;

        // Output the file name along with its key and iv
        cout << fileNames[i] << endl;
        cout << "AES key: " << stringToHex(aesKeyString) << "\t" << endl;
        cout << "AES iv:  " << stringToHex(aesIVString) << "\t" << endl << endl;

        // Encrypt all necessary AES decryption data using the public RSA key
        string encryptedAESData = stringToHex(rsaEncrypt(aesData));

        // Deletes the previous data and writes the encrypted data to the file
        writeAlteredContents(DIRPATH + fileNames.at(i), encryptedAESData + "\n" + cipherText);
    }
}


/**
 * Takes the contents of the file stored in the given string 'contents', encrypts those contents, and returns them
 */
string aesEncryptContents(const SecByteBlock& key, const SecByteBlock& iv, const string& contents) {
    string cipherText;

    // Create Cipher Text
    CryptoPP::AES::Encryption aesEncryption(key, KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(contents.c_str()), contents.length());
    stfEncryptor.MessageEnd();

    return cipherText;
}


/**
 * Uses the public key to encrypt the given input, then returns the encrypted data
 */
string rsaEncrypt(const string& input) {
    AutoSeededRandomPool rng;

    // Setup the public key using the hardcoded global public key
    RSA::PublicKey publicKey;
    StringSource publicSS(hexToString(PUBLIC_KEY_HEX), true);
    publicKey.BERDecode(publicSS);

    // Initialize vital encryption variables
    RSAES_OAEP_SHA_Encryptor e(publicKey);
    SecByteBlock plainText((const byte*)input.data(), input.size());
    size_t ecl = e.CiphertextLength( input.size() );
    SecByteBlock cipherText( ecl);

    // Use the above variables to encrypt the input and store it in the cipherText
    e.Encrypt(rng, plainText, plainText.size(), cipherText);

    // Convert the cipherText from SecByteBlock to string so it can be returned and easily used
    string cipherTextString(reinterpret_cast<const char*>(cipherText.data()), cipherText.size());

    return cipherTextString;
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
 * This function is effectively the main for decryption.
 * It iterates through all the files in the target directory doing the following for each:
 * 1. Pulls the aesData from the file and decrypts it using the RSA private key
 * 2. Uses that decrypted aesData to decrypt the encrypted contents of the file
 * 3. Erases all the encrypted data from the file and writes the plaintext back in
 */
void aesDecrypt() {
    vector<string> fileNames = getFileNames();

    for (int i = 0; i < fileNames.size(); ++i) {
        string allContents = readfileContents(DIRPATH + fileNames.at(i));

        // Change hex we pulled from the file back into a string
        string encryptedAESData = hexToString(allContents.substr(0, allContents.find_first_of("\n")));
        
        // Decrypt the string using the RSA private key
        string aesData = rsaDecrypt(encryptedAESData);

        // Turn the keyHex and ivHex back into strings to they can be turned into SecByteBlocks
        string keyString = aesData.substr(0, KEYLENGTH);
        string ivString = aesData.substr(KEYLENGTH);

        // Turn the keyString and ivString back into usable SecByteBlocks
        SecByteBlock key((const byte*)keyString.data(), keyString.size());
        SecByteBlock iv((const byte*)ivString.data(), ivString.size());

        // Separate the original file contents from the AES data
        string fileContents = allContents.substr(allContents.find_first_of("\n") + 1);

        // Decrypts contents and stores them in plaintext
        string plainText = aesDecryptContents(fileContents, key, iv);

        // Delete the encrypted contents from the file, and write the decrypted contents back in
        writeAlteredContents(DIRPATH + fileNames.at(i), plainText);
    }
}


/**
 * Uses the private key to decrypt the given input, then returns the decrypted data
 */
string rsaDecrypt(const string& input) {
    AutoSeededRandomPool rng;

    // Setup the private key using the hardcoded global private key
    RSA::PrivateKey privateKey;
    StringSource privateSS(hexToString(PRIVATE_KEY_HEX), true);
    privateKey.BERDecode(privateSS);

    // Decryption
    string decryptedString;

    RSAES_OAEP_SHA_Decryptor d(privateKey);

    StringSource ss2(input, true,
        new PK_DecryptorFilter(rng, d,
            new StringSink(decryptedString)
        ) // PK_DecryptorFilter
    ); // StringSource

    return decryptedString;
}


/**
 * Decrypts the given string using the given key and iv
 */
string aesDecryptContents(const string& contents, const SecByteBlock& key, const SecByteBlock& iv) {
    string plainText;

    CryptoPP::AES::Decryption aesDecryption(key, KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(plainText));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(contents.c_str()), contents.length());
    stfDecryptor.MessageEnd();

    return plainText;
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
 * Opens the given directory and writes all the file names in that directory into a vector for
 * later use. Notice, it does not read in the current directory (.) or the previous directory (..)
 */
vector<string> getFileNames() {
    DIR* dir;
    dirent* pdir;
    vector<string> files;

    dir = opendir(DIRPATH.c_str());

    // Reads everything in the directory and puts the names in a vector, excluding '.' and '..'
    while (pdir = readdir(dir)) {
        if ((string)pdir->d_name != "." && (string)pdir->d_name != "..") {
            files.push_back(pdir->d_name);
        }
    }

    return files;
}


/**
 * Opens the file at the given fileName and reads in the contents, then returns them
 */
string readfileContents(const string& filePath) {
    fstream file;

    file.open(filePath, fstream::in | ios::binary);
    string contents((istreambuf_iterator<char>(file)), (istreambuf_iterator<char>()));
    file.close();

    return contents;
}


/**
 * Opens and clears the file at the given fileName, writes in the given cipherText, 
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
    cout << "PID: " << ::getpid() << endl << endl;

    // Checks to make sure the user entered all the necessary arguments
    if (argc != 5) {
        cout << "First argument should be:" << endl;
        cout << "e" << "\t" << "Encrypt" << endl;
        cout << "d" << "\t" << "Decrypt" << endl << endl;
        cout << "Second argument should be:" << endl;
        cout << "128" << "\t" << "128-bit AES key" << endl;
        cout << "192" << "\t" << "192-bit AES key" << endl;
        cout << "256" << "\t" << "256-bit AES key" << endl << endl;
        cout << "Third argument should be:" << endl;
        cout << "1024" << "\t" << "1024-bit RSA keys" << endl;
        cout << "2048" << "\t" << "2048-bit RSA keys" << endl;
        cout << "3072" << "\t" << "3072-bit RSA keys" << endl << endl;
        cout << "Fourth argument should be the path from root to the target directory" << endl << endl;
        return 1;
    }

    // Checks to make sure the dirPath ends with a '/' so that the file names can be appended
    string dirPath = argv[4];
    if (dirPath[dirPath.length() - 1] != '/') {
        dirPath += "/";
    }
    DIRPATH = dirPath;

    // Sets the keysize according to the size given by the user. If the user's given
    // keysize does not match a possible keysize, it prints instructions to console and quits
    switch (atoi(argv[3])) {
    case 1024:
        PUBLIC_KEY_HEX = PUBLIC_KEY_HEX_1024;
        PRIVATE_KEY_HEX = PRIVATE_KEY_HEX_1024;
        break;
    case 2048:
        PUBLIC_KEY_HEX = PUBLIC_KEY_HEX_2048;
        PRIVATE_KEY_HEX = PRIVATE_KEY_HEX_2048;
        break;
    case 3072:
        PUBLIC_KEY_HEX = PUBLIC_KEY_HEX_3072;
        PRIVATE_KEY_HEX = PRIVATE_KEY_HEX_3072;
        break;
    default:
        cout << "Third argument should be:" << endl;
        cout << "1024" << "\t" << "1024-bit RSA keys" << endl;
        cout << "2048" << "\t" << "2048-bit RSA keys" << endl;
        cout << "3072" << "\t" << "3072-bit RSA keys" << endl << endl;
        return 1;
        break;
    }

    // Sets the keysize according to the size given by the user. If the user's given
    // keysize does not match a possible keysize, it prints instructions to console and quits
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
        return 1;
        break;
    }

    // Checks to ensure that the user has specified whether they want to aesEncrypt or aesDecrypt,
    // Else it tells them to do so
    if ((string)argv[1] == "e") {
        aesEncrypt();
    }
    else if ((string)argv[1] == "d") {
        aesDecrypt();
    }
    else {
        cout << "First argument should be:" << endl;
        cout << "e" << "\t" << "Encrypt" << endl;
        cout << "d" << "\t" << "Decrypt" << endl;
        return 1;
    }

    return 0;
}