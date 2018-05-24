#include "include/native.h"

//Release 签名MD5值
const char *RELEASE_SIGN_MD5 = "0DE8CE26215E9076009FE87C0BF2829B";


//获取app包名
int PidToName(int pid, char *lpOutBuf) {
    if (lpOutBuf == NULL) {
        return 0;
    }
    int nLen = 0;
    char filename[256] = {0};
    char cmdline[0x200] = {0};
    sprintf(filename, "/proc/%d/cmdline", pid);
    FILE *fp = fopen(filename, "r");
    if (fp) {
        if (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
            char *p = strchr(cmdline, ':');
            if (p) {
                *p = 0;
            }
            strcpy(lpOutBuf, cmdline);
            nLen = strlen(cmdline);
        } else {
            nLen = 0;
        }

        fclose(fp);
    }
    return nLen;
}


//获取apk的安装路径，不用系统api是为了防止hook
char *getpacknameTopath(char *packname, char *pOut) {
    FILE *fr = fopen("/proc/self/maps", "r");
    if (NULL == fr) {
        return NULL;
    }

    char szfindbuf[256] = "/data/app/";
    char szbuf[256] = {0};
    strncat(szfindbuf, packname, sizeof(szfindbuf));
    char *ppath = NULL;
    char *ptmp = NULL;
    while (!feof(fr))  //当文件有多行时要做的判断 判断是否到末尾
    {
        memset(szbuf, 0, sizeof(szbuf));
        if (fgets(szbuf, sizeof(szbuf), fr)) {
            if ((ppath = strstr(szbuf, szfindbuf))
                && (ptmp = strstr(szbuf, "base.apk"))) {
                ptmp[strlen("base.apk")] = 0;
                strcpy(pOut, ppath);
                fclose(fr);
                LOGI("the path  is:%s", ppath);
                return pOut;
            }
        }
    }
    fclose(fr);
    return NULL;
}


struct zip *APKArchive;
int ECsigoffset = 0;

//apk 签名文件路径
char *findApkSignFile(const char *apkPath, char *sigdir, char *pOut) {
    // LOGI("Loading APK %s", apkPath);
    APKArchive = zip_open(apkPath, 0, NULL);
    if (APKArchive == NULL) {
        //LOGI("Error loading APK");
        return NULL;
    }
    //Just for debug, print APK contents
    int numFiles = zip_get_num_files(APKArchive);
    int i = 0;
    for (i = 0; i < numFiles; i++) {
        const char *name = zip_get_name(APKArchive, i, 0);
        if (name == NULL) {
            //LOGI("Error reading zip file name at index %i : %s", zip_strerror(APKArchive));
            return NULL;
        }
        //   LOGI("File %i : %s\n", i, name);
        if (0 == memcmp(sigdir, name, strlen(sigdir)) && strrchr(name, '.')
            && (0 == memcmp("RSA", strrchr(name, '.') + 1, strlen("RSA"))
                || 0
                   == memcmp("DSA", strrchr(name, '.') + 1,
                             strlen("DSA"))
                || 0
                   == memcmp("EC", strrchr(name, '.') + 1,
                             strlen("EC")))) {
            if (0 == memcmp("EC", strrchr(name, '.') + 1, strlen("EC"))) {
                ECsigoffset = 4;
            }
            strcpy(pOut, name);
            return pOut;
        }
    }
    return NULL;
}


//读取签名信息
int zipreadbuf(char *fname, char **ppbuf) {
    int nfilesize = 0;
    struct zip_stat fstat;
    struct zip_file *file = zip_fopen(APKArchive, fname, 0);
    if (file) {
        zip_stat(APKArchive, fname, 0, &fstat);
    }

    char *buffer = (char *) malloc(fstat.size + 1);
    buffer[fstat.size] = 0;
    int numBytesRead = zip_fread(file, buffer, fstat.size);;
    nfilesize = buffer[0x36 + ECsigoffset] * 0x100 + buffer[0x37 + ECsigoffset];
    if (buffer[0x36 + ECsigoffset + 2] >= 0x80) {
        ECsigoffset += 3;
        nfilesize = buffer[0x36 + ECsigoffset] * 0x100
                    + buffer[0x37 + ECsigoffset];
    }
    *ppbuf = (char *) malloc(nfilesize + 1);
    memset(*ppbuf, 0, nfilesize + 1);
    memcpy(*ppbuf, buffer + 0x38 + ECsigoffset, nfilesize);
    free(buffer);
    zip_fclose(file);
    return nfilesize;
}


int signlength = 0;
unsigned char *g_sig = NULL;

//验证签名
bool verifySign(JNIEnv *env, jobject obj) {
    char PackName[256] = {0};
    char ApkPath[256] = {0};
    //获取包名和路径
    if (PidToName(getpid(), PackName) && getpacknameTopath(PackName, ApkPath)) {
        LOGI("packName:%s  apkPath:%s", PackName, ApkPath);
        char szSigPath[256] = {0};
        if (findApkSignFile(ApkPath, "META-INF", szSigPath)) {
            //将签名文件读取到 g_sig
            signlength = zipreadbuf(szSigPath, (char **) &g_sig);
        } else {
            LOGI("zip Not Find %s", "META-INF");
            return false;
        }
        if (signlength) {
            //char* 转jbyte[]
            jbyteArray array = env->NewByteArray(signlength);
            env->SetByteArrayRegion(array, 0, signlength, (jbyte *) g_sig);
            LOGI("the signtrue length is:%d", signlength);

            //转成jstring
            jstring str = ToMd5(env, array);
            char *c_msg = (char *) env->GetStringUTFChars(str, 0);
            //输出签名字符串
            LOGI("sign MD5 string is: %s", c_msg);

            //简单比较签名
            if (strcmp(c_msg, RELEASE_SIGN_MD5) == 0) {
                LOGI("verifySign success!!!");
                return true;
            } else {
                LOGI("verifySign fail!!!");
                return false;
                //kill(getpid(), SIGABRT);
            }
        }
    }

    return false;

}


/**
 *
 * byteArrayToMd5  byte 数组转化生成MD5
 * @param env
 * @param source
 * @return j_string
 */
jstring ToMd5(JNIEnv *env, jbyteArray source) {
    // MessageDigest
    jclass classMessageDigest = env->FindClass("java/security/MessageDigest");
    // MessageDigest.getInstance()
    jmethodID midGetInstance = env->GetStaticMethodID(classMessageDigest, "getInstance",
                                                      "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    // MessageDigest object
    jobject objMessageDigest = env->CallStaticObjectMethod(classMessageDigest, midGetInstance,
                                                           env->NewStringUTF("md5"));

    jmethodID midUpdate = env->GetMethodID(classMessageDigest, "update", "([B)V");
    env->CallVoidMethod(objMessageDigest, midUpdate, source);

    // Digest
    jmethodID midDigest = env->GetMethodID(classMessageDigest, "digest", "()[B");
    jbyteArray objArraySign = (jbyteArray) env->CallObjectMethod(objMessageDigest, midDigest);

    jsize intArrayLength = env->GetArrayLength(objArraySign);
    jbyte *byte_array_elements = env->GetByteArrayElements(objArraySign, NULL);
    size_t length = (size_t) intArrayLength * 2 + 1;
    char *char_result = (char *) malloc(length);
    memset(char_result, 0, length);

    ToHexStr((const char *) byte_array_elements, char_result, intArrayLength);
    // 在末尾补\0
    *(char_result + intArrayLength * 2) = '\0';

    jstring stringResult = env->NewStringUTF(char_result);
    // release
    env->ReleaseByteArrayElements(objArraySign, byte_array_elements, JNI_ABORT);
    // 指针
    free(char_result);

    return stringResult;
}


/**
 * HexToString 将字节数组转化为对应的十六进制字符串
 * @param source
 * @param dest
 * @param sourceLen
 */
void ToHexStr(const char *source, char *dest, int sourceLen) {
    short i;
    char highByte, lowByte;

    for (i = 0; i < sourceLen; i++) {
        highByte = source[i] >> 4;
        lowByte = (char) (source[i] & 0x0f);
        highByte += 0x30;

        if (highByte > 0x39) {
            dest[i * 2] = (char) (highByte + 0x07);
        } else {
            dest[i * 2] = highByte;
        }

        lowByte += 0x30;
        if (lowByte > 0x39) {
            dest[i * 2 + 1] = (char) (lowByte + 0x07);
        } else {
            dest[i * 2 + 1] = lowByte;
        }
    }
}


jstring getString(JNIEnv *env, jobject) {
    std::string hello = "测试Jni555";
    return env->NewStringUTF(hello.c_str());
}


jstring getSig(JNIEnv *env, jobject obj, jstring str) {
    std::string hello;
    bool b = verifySign(env, obj);
    if (b) {
        hello = "匹配成功11111";
    } else {
        hello = "匹配失败eeeee";
    }
    return env->NewStringUTF(hello.c_str());
}


//native 方法集合
static JNINativeMethod gMethods[] = {
        {"stringFromJNI",   "()Ljava/lang/String;",                   (void *) getString},
        {"getSignatureStr", "(Ljava/lang/String;)Ljava/lang/String;", (void *) getSig},
};


//native 方法注册
static int registerNativeMethods(JNIEnv *env, const char *className,
                                 JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

static int registerNatives(JNIEnv *env) {
    if (!registerNativeMethods(env, JNIREG_CLASS, gMethods,
                               sizeof(gMethods) / sizeof(gMethods[0])))
        return JNI_FALSE;

    return JNI_TRUE;
}


/*
* 动态注册
*
* Returns the JNI version on success, -1 on failure.
*/
JNIEXPORT int JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    assert(env != NULL);

    if (!registerNatives(env)) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}







