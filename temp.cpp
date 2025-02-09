#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <sstream>
#include <vector>
#include <iostream>
 
using std::string;
using std::vector;
using std::cout;
using std::endl;

#define IV_SIZE 12
#define TAG_SIZE 16

std::vector<unsigned char> aes_128_gcm_encrypt(std::string plaintext, std::string key)
{
    unsigned char tag[TAG_SIZE];
    unsigned char iv[IV_SIZE];
 
    size_t cipher_length = plaintext.size() + IV_SIZE + TAG_SIZE;
    std::vector<unsigned char> output(cipher_length, '\0');
 
    int actual_size=0, final_size=0;

    EVP_CIPHER_CTX* e_ctx = EVP_CIPHER_CTX_new();
    RAND_bytes(iv, sizeof(iv));

    const unsigned char* key_pointer = (const unsigned char*)key.c_str();


    EVP_EncryptInit_ex(e_ctx, EVP_aes_128_gcm(), NULL, key_pointer, iv);
    EVP_EncryptUpdate(e_ctx, &output[IV_SIZE+TAG_SIZE], &actual_size, (const unsigned char*)plaintext.data(), plaintext.length() );
    EVP_EncryptFinal_ex(e_ctx, &output[IV_SIZE+TAG_SIZE+actual_size], &final_size);
    EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    std::copy( tag, tag+TAG_SIZE, output.begin() );
    std::copy( iv, iv+IV_SIZE, output.begin()+TAG_SIZE );

    output.resize(IV_SIZE + TAG_SIZE + actual_size+final_size);
    EVP_CIPHER_CTX_free(e_ctx);
    return output;
}
 
std::string aes_128_gcm_decrypt(std::vector<unsigned char> ciphertext, std::string key)
{
    unsigned char tag[TAG_SIZE];
    unsigned char iv[IV_SIZE];
 
    std::copy( ciphertext.begin(),    ciphertext.begin()+TAG_SIZE, tag);
    std::copy( ciphertext.begin()+TAG_SIZE, ciphertext.begin()+TAG_SIZE+IV_SIZE, iv);
    std::vector<unsigned char> plaintext; plaintext.resize(ciphertext.size(), '\0');
 
    int actual_size=0, final_size=0;
    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
    const unsigned char* key_pointer = (const unsigned char*)key.c_str();
    EVP_DecryptInit_ex(d_ctx, EVP_aes_128_gcm(), NULL, key_pointer, iv);
    EVP_DecryptUpdate(d_ctx, &plaintext[0], &actual_size, &ciphertext[TAG_SIZE+IV_SIZE], ciphertext.size()-TAG_SIZE-IV_SIZE );
    EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int n = EVP_DecryptFinal_ex(d_ctx, &plaintext[actual_size], &final_size);
    cout << "n: " << n << endl;
    EVP_CIPHER_CTX_free(d_ctx);
    plaintext.resize(actual_size + final_size);
 
    return string(plaintext.begin(),plaintext.end());

}

int aes_128_gcm_tag_verify(std::vector<unsigned char> ciphertext, std::string key)
{
    unsigned char tag[TAG_SIZE];
    unsigned char iv[IV_SIZE];
 
    std::copy( ciphertext.begin(),    ciphertext.begin()+TAG_SIZE, tag);
    std::copy( ciphertext.begin()+TAG_SIZE, ciphertext.begin()+TAG_SIZE+IV_SIZE, iv);
    
    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
    const unsigned char* key_pointer = (const unsigned char*)key.c_str();

    EVP_DecryptInit_ex(d_ctx, EVP_aes_128_gcm(), NULL, key_pointer, iv);

    EVP_DecryptUpdate(d_ctx, NULL, nullptr, &ciphertext[TAG_SIZE+IV_SIZE], ciphertext.size()-TAG_SIZE-IV_SIZE);

    EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    int verify = EVP_DecryptFinal_ex(d_ctx, NULL, nullptr);
    EVP_CIPHER_CTX_free(d_ctx);

    return verify;


}
 
int main(int argc, char **argv)
{
    // aes_init();
 
    //create a sample key
    unsigned char key_bytes[16];
    // RAND_bytes(key_bytes, sizeof(key_bytes));
    string key = "1234567890ABCDEF";
 
    //text to encrypt
    string plaintext= "elephants in space";
    cout << plaintext << endl;
 
    //encrypt
    vector<unsigned char> ciphertext = aes_128_gcm_encrypt(plaintext, key);
 
    //output
    static const char *chars="0123456789ABCDEF";
    // for(int i=0; i<ciphertext.size(); i++)
    // {
    //     cout << ciphertext[i];
    //     // cout << chars[ciphertext[i]%16];
    // }

    // print the cipher text in hex
    for(int i=28; i<ciphertext.size(); i++)
    {
        cout << chars[ciphertext[i]/16];
        cout << chars[ciphertext[i]%16];
    }
    cout << endl;

    cout << plaintext.size() << endl;
    cout << ciphertext.size() - 28 << endl;
 
    // ciphertext[11] = 'a';

    // add another character to the cipher text
    // ciphertext.push_back('a');

    //decrypt
    string out = aes_128_gcm_decrypt(ciphertext, key);
    cout << out << endl;

    std::cout << "Tag Verify Function " << aes_128_gcm_tag_verify(ciphertext, key) << std::endl;
}