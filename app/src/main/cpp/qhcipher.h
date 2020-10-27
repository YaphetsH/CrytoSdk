//
// Created by yaphets on 2020/10/25.
//





#ifndef QHCIPHER_QHCIPHER_H

#define QHCIPHER_QHCIPHER_H

#endif //QHCIPHER_QHCIPHER_H
char* getPubKeyFromLocal();
char* getPriKeyFromServer();
unsigned char* Padding_Buffer_Size(unsigned char* data,int dataSize);
unsigned char* encryptReqByKey(unsigned char *data,const unsigned char* key,const unsigned  char* iv,int data_len);
unsigned char* decryptReqByKey(unsigned char *data,const unsigned char* key,const unsigned  char* iv,int data_len);

unsigned char* encryptBuffer(unsigned char* data ,int dataSize);
unsigned char* decryptBuffer(unsigned char* data ,int dataSize);
int bytetohexstring(unsigned char *in, int len, char *out);
unsigned char* hexstr_to_char(const char* hexstr);

int  getCipherMode();
int getPackSize(unsigned char* data,int start);
int  setPackInfo(unsigned char* data,int dataSize,int main,int sub);
int  getMainCommand(unsigned char*data,int start);
int  getSubConmmand(unsigned char*data,int start);
void reset();