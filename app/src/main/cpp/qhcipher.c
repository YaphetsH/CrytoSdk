//
// Created by yaphets on 2020/10/25.
//

#include "qhcipher.h"
#include "openssl/crypto.h"
#include <android/log.h>
#include <jni.h>
#include <stdlib.h>
#include <stdio.h>
#include <zconf.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

#define TAG "yaphetshan"


#if 1
#define log_print_verbose(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__)
#define log_print_debug(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define log_print_info(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define log_print_warn(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define log_print_error(...) __android_log_print(ANROID_LOG_ERROR, TAG, __VA_ARGS__)
#else
#define log_print_verbose(...)
#define log_print_debug(...)
#define log_print_info(...)
#define log_print_warn(...)
#define log_print_error(...)
#endif

#define LOGV(...) log_print_verbose(__VA_ARGS__)
#define LOGD(...) log_print_debug(__VA_ARGS__)
#define LOGI(...) log_print_info(__VA_ARGS__)
#define LOGW(...) log_print_warn(__VA_ARGS__)

JNIEXPORT jstring JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_hellpCipher(JNIEnv *env, jobject thiz) {

    LOGD("Hello,Version");

    return (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_VERSION));

}

unsigned char* encryptBuffer(unsigned char* data,int dataSize) {

    char* pub_key = getPubKeyFromLocal();

    int encryptedValueSize = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;

    //BIO_new_mem_buf() creates a memory BIO using len bytes of data at buf,
    // if len is -1 then the buf is assumed to be nul terminated and its length is determined by strlen.
    BIO *keyBio = BIO_new_mem_buf((void *) pub_key, -1);
    //The RSA structure consists of several BIGNUM components.
    // It can contain public as well as private RSA keys:
    RSA *publicKey = PEM_read_bio_RSA_PUBKEY(keyBio, NULL, NULL, NULL);
    //释放BIdO
    BIO_free_all(keyBio);

    //RSA_size returns the RSA modulus size in bytes.
    // It can be used to determine how much memory must be allocated for an RSA encrypted value.
    int flen = RSA_size(publicKey);

    //复制src到srcOrigin
    unsigned char *srcOrigin = (unsigned char *) malloc(dataSize);
    memset(srcOrigin, 0, dataSize);
    memcpy(srcOrigin, data, dataSize);
    //每次加密后的长度
    unsigned char *encryptedValue = (unsigned char *) malloc(flen);

    desText_len = flen * (dataSize / (flen - 11) + 1);

    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    //对数据进行公钥加密运算
    //对于1024bit，2048应该为256
    //RSA_PKCS1_PADDING 最大加密长度 为 128 -11
    //RSA_NO_PADDING 最大加密长度为  128
    //rsa_size = rsa_size - RSA_PKCS1_PADDING_SIZE;

    for (int i = 0; i <= dataSize / (flen - 11); i++) {
        src_flen = (i == dataSize / (flen - 11)) ? dataSize % (flen - 11) : flen - 11;
        if (src_flen == 0) {
            break;
        }
        //重置encryptedValue
        memset(encryptedValue, 0, flen);
        //encrypt srcOrigin + src_offset到encryptedValue
        //returns the size of the encrypted data
        encryptedValueSize = RSA_public_encrypt(src_flen, srcOrigin + src_offset, encryptedValue,
                                                publicKey, RSA_PKCS1_PADDING);
        if (encryptedValueSize == -1) {
            RSA_free(publicKey);
            CRYPTO_cleanup_all_ex_data();
            free(srcOrigin);
            free(encryptedValue);
            free(desText);

            return NULL;
        }

        //复制encryptedValue到desText + cipherText_offset

        memcpy(desText + cipherText_offset, encryptedValue, encryptedValueSize);
        cipherText_offset += encryptedValueSize;
        src_offset += src_flen;
    }

    RSA_free(publicKey);
    //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
    CRYPTO_cleanup_all_ex_data();

    unsigned char *cipher = (unsigned char *) malloc(cipherText_offset);
    //填充0
    memset(cipher, 0, cipherText_offset);
    memcpy(cipher,desText,cipherText_offset);
    unsigned char* out_data = Padding_Buffer_Size(cipher,cipherText_offset);


    //释放内存
    free(cipher);
    free(srcOrigin);
    free(encryptedValue);
    free(desText);

    return out_data;

}
unsigned char* decryptBuffer(unsigned char* data ,int dataSize){


   char* pri_key = getPriKeyFromServer();

    int ret = 0, src_flen = 0, plaintext_offset = 0, descText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

    keybio = BIO_new_mem_buf((void *) pri_key, -1);
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    descText_len = (flen - 11) * (dataSize / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(dataSize);
    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(descText_len);
    memset(desText, 0, descText_len);

    memset(srcOrigin, 0, dataSize);
    memcpy(srcOrigin, data, dataSize);

    for (int i = 0; i <= dataSize / flen; i++) {
        src_flen = (i == dataSize / flen) ? dataSize % flen : flen;
        if (src_flen == 0) {
            break;
        }

        memset(plaintext, 0, flen - 11);
        ret = RSA_private_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa,
                                  RSA_PKCS1_PADDING);
        if (ret == -1) {
            RSA_free(rsa);
            CRYPTO_cleanup_all_ex_data();
            free(srcOrigin);
            free(plaintext);
            free(desText);
            LOGD("%s","fail");
            return NULL;
        }
        memcpy(desText + plaintext_offset, plaintext, ret);
        plaintext_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
    CRYPTO_cleanup_all_ex_data();

    unsigned char *decrypt = (unsigned char *) malloc(plaintext_offset);
    //填充0
    memset(decrypt, 0, plaintext_offset);

    memcpy(decrypt,desText,plaintext_offset);

    unsigned char* out_data = Padding_Buffer_Size(decrypt,plaintext_offset);
    free(decrypt);
    free(srcOrigin);
    free(plaintext);
    free(desText);
    return out_data;
}
int mystrlen(unsigned char* str)
{
    int i = -1;
    while(i++,'\0' != str[i]);
    return i;
}
unsigned char* Padding_Buffer_Size(unsigned  char* data,int dataSize){
    unsigned char* ret_data = (unsigned char*) calloc(1,dataSize+4);

    memcpy(ret_data+4,data,dataSize);
    LOGD("%d",mystrlen(data));

    //ret_data[0] = mystrlen(dataSize);
    return data;
}


unsigned char* encryptReqByKey(unsigned char *data,const unsigned char* key_str,const unsigned  char* iv_str,int data_len){
    LOGI("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
    const unsigned char *iv = (const unsigned char *) iv_str;
    const unsigned char *key = key_str;
    unsigned char  *src = data;
    int src_Len = data_len;

    int outlen = 0, cipherText_len = 0;

    unsigned char *out = (unsigned char *) malloc((src_Len / 16 + 1) * 16);

    //清空内存空间
    memset(out, 0, (src_Len / 16 + 1) * 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    LOGI("AES->指定加密算法，初始化加密key/iv");
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) key, iv);
    LOGI("AES->进行加密操作");
    EVP_EncryptUpdate(ctx, out, &outlen, (const unsigned char *) src, src_Len);
    cipherText_len = outlen;

    LOGI("AES->结束加密操作");
    EVP_EncryptFinal_ex(ctx, out + outlen, &outlen);
    cipherText_len += outlen;

    LOGI("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(ctx);
    LOGI("AES->释放内存");
//Padding_Buffer_Size(out,cipherText_len);
    unsigned char* cipher = (unsigned char*)malloc(cipherText_len);
    memset(cipher,0,cipherText_len);
    memcpy(cipher,out,cipherText_len);

    free(out);
    return cipher;
}
unsigned char* decryptReqByKey(unsigned char *data,const unsigned char* key_str,const unsigned  char* iv_str,int data_len){
    LOGI("AES->对称密钥，也就是说加密和解密用的是同一个密钥");
    const unsigned char *iv = iv_str;
    const unsigned char *key = key_str;
    unsigned char *src = data;
    int src_Len = data_len;

    int outlen = 0, plaintext_len = 0;

    unsigned char *out  = (unsigned char *) malloc(src_Len);
    memset(out, 0, src_Len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    LOGI("AES->指定解密算法，初始化解密key/iv");
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *) key, iv);
    LOGI("AES->进行解密操作");
    EVP_DecryptUpdate(ctx, out, &outlen, (const unsigned char *) src, src_Len);
    plaintext_len = outlen;

    LOGI("AES->结束解密操作");
    EVP_DecryptFinal_ex(ctx, out + outlen, &outlen);
    plaintext_len += outlen;

    LOGI("AES->EVP_CIPHER_CTX_cleanup");
    EVP_CIPHER_CTX_cleanup(ctx);
   // unsigned char* cipher = Padding_Buffer_Size(out,plaintext_len);
    unsigned char* cipher = (unsigned char*)calloc(1,plaintext_len);
    memcpy(cipher,out,plaintext_len);
    LOGI("AES->释放内存");
    free(out);

    return cipher;
}


char* getPubKeyFromLocal(){
    char* keys = "-----BEGIN PUBLIC KEY-----\n"
                 "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDn76Br3a02GFjGxetapBRvBuZ/\n"
                 "5cXCUaGFDiRUmhfuJ4yff1mcLriOfymTmWjjBKTVMD0ML1C6SqckFMz+5vasu6p8\n"
                 "5mbtKSyUHn3cbEb4aLFo4yUeV8HnLcI5vo52SqjFuUUSTODEWUNGkNwLENWh+lI1\n"
                 "9zHlPfA+BqiAiJ6vCwIDAQAB\n"
                 "-----END PUBLIC KEY-----";
    return keys;
}
char* getPriKeyFromServer(){
    char* keys = "-----BEGIN RSA PRIVATE KEY-----\n"
                 "MIICXAIBAAKBgQDn76Br3a02GFjGxetapBRvBuZ/5cXCUaGFDiRUmhfuJ4yff1mc\n"
                 "LriOfymTmWjjBKTVMD0ML1C6SqckFMz+5vasu6p85mbtKSyUHn3cbEb4aLFo4yUe\n"
                 "V8HnLcI5vo52SqjFuUUSTODEWUNGkNwLENWh+lI19zHlPfA+BqiAiJ6vCwIDAQAB\n"
                 "AoGAWwCIXwpBVgJDgupRJ+VNJyr78Z7D8zR4PW6JDrDPRuA5qrMbA87JFxAJziHZ\n"
                 "J4nA6uzcZxWBhTaZUezfafxROEG8lFeN1Xtrf0a8OPGJS8S2SH9TFpWYC7KCO7sM\n"
                 "L5rYQt/FrXS6AxLX91IyloEVKSpcY4sSr2qKDEN5VlToR6ECQQD5liNUGVH+ttQg\n"
                 "aOviUGiTBCTRIKfEce1wO/vyX5ocYUE5J73/54Ft2CvHnkNGb03jqUbMCVbMgvLs\n"
                 "SMuhFh3TAkEA7eVg1npREDUC5GvLyPXP6MVyNXa3HwYhqDM1cSY2Sgl/H8IVVkcO\n"
                 "lYfLk8KpY6kbzc8Lpauq7ItFl6PYXTQO6QJBALQWmTc9beSUl0sracjKrCooe0hK\n"
                 "f8NHUUQChDDGurRvmFhdTMMxkDpqGGzYzUItXc4/fk4LDw5SDmZfwE5jXvECQCLx\n"
                 "IAogqStyPdyDIMmBoWoVJjNIHpmF8webjevyquKxBmUJwsyLX08DRRmM7AhhXF4c\n"
                 "XR+WWWKpCi29uRfnf5ECQBj1vJZR/S8CbFIBO6+NJj/N9VdMOIMY48SNF2IROhC/\n"
                 "EEuHYfr+3d4hwGIElYyf2sTaVz7/GtvZ6k9cGgYg3go=\n"
                 "-----END RSA PRIVATE KEY-----";
    return keys;
}

int getCipherMode() {

    return  2;
}
int getMainCommand(Byte* data, int start) {
    int cmd_one = *(data + start +5)<<8;
    int cmd_two = *(data + start +4);
    return cmd_one|cmd_two;
}
int getSubConmmand(Byte* data, int start) {
    int cmd_one = *(data + start +7)<<8;

    int cmd_two = *(data + start +6);

    return cmd_one|cmd_two;
}

int setPackInfo(Byte *data, int dataSize, int main, int sub) {
    data[2] = dataSize;
    data[4] = main;
    data[6] = sub;
    data[3] = dataSize>>16;
    data[5] = main>>16;
    data[7] = sub>>16;

    return data;



}
int getPackSize(unsigned char * data, int start) {

    int size_one = *(unsigned char *)(data+start+3)<<8;
    int size_two = *(unsigned char *)(data+start+2);
    return size_one|size_two;

}
unsigned char* hexstr_to_char(const char* hexstr)
{
    size_t len = strlen(hexstr);
    if(len % 2 != 0)
        return NULL;
    size_t final_len = len / 2;
    unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
    for (size_t i=0, j=0; j<final_len; i+=2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    chrs[final_len] = '\0';
    return chrs;
}

int bytetohexstring(unsigned char *in, int len, char *out) {
    for (int i = 0; i < len; i++) {
        if ((in[i] >> 4) >= 10 && (in[i] >> 4) <= 15)
            out[2*i] = (in[i] >> 4) + 'A' - 10;
        else
            out[2*i] = (in[i] >> 4) | 0x30;

        if ((in[i] & 0x0f) >= 10 && (in[i] & 0x0f) <= 15)
            out[2*i+1] = (in[i] & 0x0f) + 'A' - 10;
        else
            out[2*i+1] = (in[i] & 0x0f) | 0x30;
    }
    return 0;
}

JNIEXPORT jbyteArray JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_decryptBuffer(JNIEnv *env, jclass clazz, jbyteArray data,
jint size) {
unsigned  char* src = (*env)->GetByteArrayElements(env,data, NULL);
unsigned char* result = decryptBuffer(src,size);
jbyteArray jarray = (*env)->NewByteArray(env,30);
(*env)->SetByteArrayRegion(env,jarray, 0, 30, result);

return jarray;

}
JNIEXPORT jbyteArray JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_encryptBuffer(JNIEnv *env, jclass clazz, jbyteArray data,jint size) {
    unsigned char *src = (*env)->GetByteArrayElements(env, data, NULL);
    unsigned char* test = hexstr_to_char("02681a001838d20c89e6b04c57fe1493f1269f81cc0d59ba496b");
    unsigned char* result = encryptBuffer(src,size);
    jbyteArray jarray = (*env)->NewByteArray(env, 132);
    (*env)->SetByteArrayRegion(env, jarray, 0,132,result);
    return jarray;

}

JNIEXPORT jint JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_getCipherMode(JNIEnv *env, jclass clazz) {
    // TODO: implement getCipherMode()
    getCipherMode();
}
JNIEXPORT jint JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_getPackSize(JNIEnv *env, jclass clazz, jbyteArray data,jint start) {
    // TODO: implement getPackSize()

    unsigned char * cData = (*env)->GetByteArrayElements(env,data, NULL);
    int result = getPackSize(cData,start);
    (*env)->ReleaseByteArrayElements(env,data, cData, 0 );
    return result;
}

JNIEXPORT jint JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_setPackInfo(JNIEnv *env, jclass clazz, jbyteArray data,
                                   jint data_size, jint main, jint sub) {
    jbyte* cData = (*env)->GetByteArrayElements(env,data, NULL);
    int result = setPackInfo(cData,data_size,main,sub);
    (*env)->ReleaseByteArrayElements(env,data, cData, 0 );

    return result;

}

JNIEXPORT jbyteArray JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_aesdecrypt(JNIEnv *env, jclass clazz, jbyteArray data,
                                                   jint size) {
    unsigned char* result = decryptReqByKey(data,"JA2F8AKJF3D7HF12","0123456789012345",size);
    jbyteArray jarray = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, jarray, 0,32,result);
    return jarray;
}

JNIEXPORT jbyteArray JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_aesencrypt(JNIEnv *env, jclass clazz, jbyteArray data,
                                                   jint size) {
    //unsigned char* test = hexstr_to_char("02681a001838d20c89e6b04c57fe1493f1269f81cc0d59ba496b");
    unsigned char* result = encryptReqByKey(data,"JA2F8AKJF3D7HF12","0123456789012345",size);
    jbyteArray jarray = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, jarray, 0,32,result);
    return jarray;

}
