//
// Created by admin on 2018/5/23.
//

#ifndef SIGNATUREDEMO_DATA_LOCK_H
#define SIGNATUREDEMO_DATA_LOCK_H

#include <jni.h>
#include <string>
#include <malloc.h>
#include<android/log.h>
#include <unistd.h>
#include <assert.h>
#include "../zip/include/zip.h"
#include "log.h"

//指定要注册的类 即nativie方法所在的类
#define JNIREG_CLASS "com/zto/libsignature/SignatureUtil"

__BEGIN_DECLS

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved);
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved);

bool verifySign(JNIEnv *env, jobject obj);

jstring ToMd5(JNIEnv *env, jbyteArray source);

void ToHexStr(const char *source, char *dest, int sourceLen);


__END_DECLS




#endif //SIGNATUREDEMO_DATA_LOCK_H
