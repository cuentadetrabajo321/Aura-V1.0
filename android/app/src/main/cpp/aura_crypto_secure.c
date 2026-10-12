#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define AURA_MODEL_MAX_CIPHERTEXT (5U * 1024U * 1024U + 16U)

void
aura_secure_mem_clear (void *buffer, size_t length)
{
    volatile unsigned char *bytes = (volatile unsigned char *)buffer;

    while (buffer && length--)
        *bytes++ = 0;
}

static void
clear_java_array (JNIEnv *env, jbyteArray array, jsize expected_length)
{
    jbyte zeroes[32] = { 0 };
    jsize length;

    if (!array)
        return;
    length = (*env)->GetArrayLength (env, array);
    if (length != expected_length || length > (jsize)sizeof (zeroes))
        return;
    (*env)->SetByteArrayRegion (env, array, 0, length, zeroes);
}

static void
clear_pending_exception_while_wiping (JNIEnv *env, jbyteArray key_bytes,
                                      jbyteArray iv_bytes,
                                      jbyteArray java_key,
                                      jbyteArray java_iv, jthrowable error)
{
    if ((*env)->ExceptionCheck (env))
        (*env)->ExceptionClear (env);
    clear_java_array (env, key_bytes, 32);
    clear_java_array (env, iv_bytes, 16);
    clear_java_array (env, java_key, 32);
    clear_java_array (env, java_iv, 16);
    if (error)
        (*env)->Throw (env, error);
}

JNIEXPORT jbyteArray JNICALL
Java_com_aura_cyberdefense_AuraCryptoSecure_decryptModelNative (
    JNIEnv *env, jobject thiz, jbyteArray encrypted_data, jbyteArray key_bytes,
    jbyteArray iv_bytes)
{
    jbyte *ciphertext = NULL;
    jbyte *key = NULL;
    jbyte *iv = NULL;
    jbyteArray java_ciphertext = NULL;
    jbyteArray java_key = NULL;
    jbyteArray java_iv = NULL;
    jbyteArray plaintext = NULL;
    jclass secure_class = NULL;
    jmethodID decrypt_method = NULL;
    jthrowable pending_exception = NULL;
    jsize ciphertext_length = 0;
    jsize key_length = 0;
    jsize iv_length = 0;

    if (!encrypted_data || !key_bytes || !iv_bytes)
        goto cleanup;

    ciphertext_length = (*env)->GetArrayLength (env, encrypted_data);
    key_length = (*env)->GetArrayLength (env, key_bytes);
    iv_length = (*env)->GetArrayLength (env, iv_bytes);
    if (ciphertext_length < 16 ||
        ciphertext_length > (jsize)AURA_MODEL_MAX_CIPHERTEXT ||
        (ciphertext_length % 16) != 0 || key_length != 32 || iv_length != 16)
        goto cleanup;

    ciphertext = malloc ((size_t)ciphertext_length);
    key = malloc (32);
    iv = malloc (16);
    if (!ciphertext || !key || !iv)
        goto cleanup;

    (*env)->GetByteArrayRegion (env, encrypted_data, 0, ciphertext_length,
                                ciphertext);
    (*env)->GetByteArrayRegion (env, key_bytes, 0, key_length, key);
    (*env)->GetByteArrayRegion (env, iv_bytes, 0, iv_length, iv);
    if ((*env)->ExceptionCheck (env))
        goto cleanup;

    java_ciphertext = (*env)->NewByteArray (env, ciphertext_length);
    java_key = (*env)->NewByteArray (env, key_length);
    java_iv = (*env)->NewByteArray (env, iv_length);
    if (!java_ciphertext || !java_key || !java_iv)
        goto cleanup;

    (*env)->SetByteArrayRegion (env, java_ciphertext, 0, ciphertext_length,
                                ciphertext);
    (*env)->SetByteArrayRegion (env, java_key, 0, key_length, key);
    (*env)->SetByteArrayRegion (env, java_iv, 0, iv_length, iv);
    if ((*env)->ExceptionCheck (env))
        goto cleanup;

    secure_class = (*env)->GetObjectClass (env, thiz);
    if (!secure_class)
        goto cleanup;
    decrypt_method = (*env)->GetMethodID (
        env, secure_class, "decryptWithPlatformCipher", "([B[B[B)[B");
    if (!decrypt_method)
        goto cleanup;

    plaintext = (jbyteArray)(*env)->CallObjectMethod (
        env, thiz, decrypt_method, java_ciphertext, java_key, java_iv);
    if ((*env)->ExceptionCheck (env))
        goto cleanup;
    if (!plaintext)
        goto cleanup;

cleanup:
    if ((*env)->ExceptionCheck (env))
        pending_exception = (*env)->ExceptionOccurred (env);

    if (key)
        aura_secure_mem_clear (key, 32);
    if (iv)
        aura_secure_mem_clear (iv, 16);
    if (ciphertext)
        aura_secure_mem_clear (ciphertext,
                              ciphertext_length > 0
                                  ? (size_t)ciphertext_length
                                  : 0);
    free (key);
    free (iv);
    free (ciphertext);

    if (pending_exception) {
        clear_pending_exception_while_wiping (env, key_bytes, iv_bytes,
                                              java_key, java_iv,
                                              pending_exception);
        (*env)->DeleteLocalRef (env, pending_exception);
    } else {
        clear_java_array (env, key_bytes, 32);
        clear_java_array (env, iv_bytes, 16);
        clear_java_array (env, java_key, 32);
        clear_java_array (env, java_iv, 16);
    }

    if (java_ciphertext)
        (*env)->DeleteLocalRef (env, java_ciphertext);
    if (java_key)
        (*env)->DeleteLocalRef (env, java_key);
    if (java_iv)
        (*env)->DeleteLocalRef (env, java_iv);
    if (secure_class)
        (*env)->DeleteLocalRef (env, secure_class);

    return plaintext;
}
