//
// Created by admin on 2018/5/23.
//

#ifndef SIGNATUREDEMO_NATIVE_H
#define SIGNATUREDEMO_NATIVE_H

#include <jni.h>
#include <string>
#include <malloc.h>
#include<android/log.h>
#include <unistd.h>
#include <assert.h>
#include "../zip/include/zip.h"
#include "log.h"

//指定要注册的类 即nativie方法所在的类
#define JNIREG_CLASS "com/zto/encrypt/DataLock"

__BEGIN_DECLS

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved);

__END_DECLS

bool verifySign(JNIEnv *env, jobject obj);

jstring ToMd5(JNIEnv *env, jbyteArray source);

void ToHexStr(const char *source, char *dest, int sourceLen);


#endif //SIGNATUREDEMO_NATIVE_H
