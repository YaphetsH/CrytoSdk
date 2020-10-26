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
int getPackSize(unsigned int * data,int start);
int  setPackInfo(Byte* data,int dataSize,int main,int sub);
int  getMainCommand(Byte *data,int start);
int  getSubConmmand(Byte *data,int start);
JNIEXPORT jstring JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_hellpCipher(JNIEnv *env, jobject thiz) {

    LOGD("Hello,Version");

    return (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_VERSION));

}

int encryptBuffer(jbyteArray data, int dataSize) {
    int size = sizeof(data);
    return size;

}

int decryptBuffer(jbyteArray data, int dataSize) {}

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

int getPackSize(unsigned int * data, int start) {

   int size_one = *(unsigned int *)(data+start+3)<<8;
   int size_two = *(unsigned int *)(data+start+2);
   LOGD("%d",size_one);
   return size_one|size_two;

}


void reset() {

}

JNIEXPORT jbyteArray JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_encryptBuffer(JNIEnv *env, jclass clazz, jbyteArray data,jint size) {

    return encryptBuffer(data,size);

}

JNIEXPORT jbyteArray JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_decryptBuffer(JNIEnv *env, jclass clazz, jbyteArray data,
                                                      jint size) {
    // TODO: implement decryptBuffer()
}



JNIEXPORT jint JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_getCipherMode(JNIEnv *env, jclass clazz) {
    // TODO: implement getCipherMode()
    getCipherMode();
}


JNIEXPORT jint JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_getPackSize(JNIEnv *env, jclass clazz, jbyteArray data,
                                                    jint start) {
    // TODO: implement getPackSize()

    jbyte* cData = (*env)->GetByteArrayElements(env,data, NULL);
    LOGD("%d",cData[2]);
    int result = getPackSize((unsigned int *)cData,start);
    (*env)->ReleaseByteArrayElements(env,data, cData, 0 );

    return result;
    //int size =  getPackSize(data,start);
}

JNIEXPORT jint JNICALL
Java_com_yaphetsh_qhcipher_NativeHelper_setPackInfo(JNIEnv *env, jclass clazz, jbyteArray data,
                                   jint data_size, jint main, jint sub) {
    jbyte* cData = (*env)->GetByteArrayElements(env,data, NULL);
    int result = setPackInfo(cData,data_size,main,sub);
    (*env)->ReleaseByteArrayElements(env,data, cData, 0 );

    return result;

}