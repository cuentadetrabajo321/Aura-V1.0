/*
 ============================================================================
 Name        : hev-jni.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2019 - 2023 hev
 Description : Jave Native Interface
 ============================================================================
 */

#ifdef __ANDROID__

#include <jni.h>
#include <pthread.h>
#include <stdatomic.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>

#include "hev-main.h"
#include "hev-socks5-tunnel.h"
#include "aura_sni_firewall.h"

#include "hev-jni.h"

/* clang-format off */
#ifndef PKGNAME
#define PKGNAME hev/htproxy
#endif
#ifndef CLSNAME
#define CLSNAME TProxyService
#endif
/* clang-format on */

#define STR(s) STR_ARG (s)
#define STR_ARG(c) #c
#define N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))

typedef struct _ThreadData ThreadData;

struct _ThreadData
{
    char *path;
    int fd;
};

static atomic_int is_running;
static int thread_joinable;
static JavaVM *java_vm;
static jclass tproxy_class;
static jmethodID dns_event_method;
static jmethodID protect_socket_method;
static pthread_t work_thread;
static pthread_mutex_t mutex;
static pthread_key_t current_jni_env;

static jboolean native_start_service (JNIEnv *env, jobject thiz,
                                      jstring conig_path, jint fd);
static jboolean native_stop_service (JNIEnv *env, jobject thiz);
static jboolean native_is_running (JNIEnv *env, jobject thiz);
static jlongArray native_get_stats (JNIEnv *env, jobject thiz);
static void native_set_blocked_ips (JNIEnv *env, jobject thiz,
                                    jobjectArray addresses);
static jboolean native_block_domain (JNIEnv *env, jobject thiz,
                                     jstring domain);
static void native_add_dynamic_sni_rule (JNIEnv *env, jclass klass,
                                         jstring domain);
static jboolean native_set_dynamic_sni_allowlist (JNIEnv *env, jobject thiz,
                                                  jobjectArray domains);

static JNINativeMethod native_methods[] = {
    { "TProxyStartService", "(Ljava/lang/String;I)Z",
      (void *)native_start_service },
    { "TProxyStopService", "()Z", (void *)native_stop_service },
    { "TProxyIsRunning", "()Z", (void *)native_is_running },
    { "TProxyGetStats", "()[J", (void *)native_get_stats },
        { "TProxySetBlockedIps", "([Ljava/lang/String;)V",
            (void *)native_set_blocked_ips },
    { "TProxyBlockDomain", "(Ljava/lang/String;)Z", (void *)native_block_domain },
    { "addDynamicSniRule", "(Ljava/lang/String;)V",
      (void *)native_add_dynamic_sni_rule },
    { "TProxySetDynamicSniAllowlist", "([Ljava/lang/String;)Z",
      (void *)native_set_dynamic_sni_allowlist },
};

static void
detach_current_thread (void *env)
{
    (*java_vm)->DetachCurrentThread (java_vm);
}

jint
JNI_OnLoad (JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    jclass klass;
    jint res;

    java_vm = vm;
    res = (*vm)->GetEnv (vm, (void **)&env, JNI_VERSION_1_4);
    if (res != JNI_OK)
        return JNI_ERR;

    klass = (*env)->FindClass (env, STR (PKGNAME) "/" STR (CLSNAME));
    if (!klass)
        return JNI_ERR;
    tproxy_class = (*env)->NewGlobalRef (env, klass);
    dns_event_method = (*env)->GetStaticMethodID (
        env, klass, "dispatchDnsEvent",
        "(Ljava/lang/String;ILjava/lang/String;I)V");
    protect_socket_method = (*env)->GetStaticMethodID (
        env, klass, "protectSocket", "(I)Z");
    res = (*env)->RegisterNatives (env, klass, native_methods,
                                   N_ELEMENTS (native_methods));
    (*env)->DeleteLocalRef (env, klass);
    if (res < 0 || !tproxy_class || !dns_event_method || !protect_socket_method)
        return JNI_ERR;

    pthread_key_create (&current_jni_env, detach_current_thread);
    pthread_mutex_init (&mutex, NULL);

    return JNI_VERSION_1_4;
}

int
hev_jni_protect_socket (int socket_fd)
{
    JNIEnv *env = NULL;
    int attached = 0;
    jint status;
    jboolean protected;

    if (!java_vm || !tproxy_class || !protect_socket_method)
        return 0;

    status = (*java_vm)->GetEnv (java_vm, (void **)&env, JNI_VERSION_1_4);
    if (status == JNI_EDETACHED) {
        if ((*java_vm)->AttachCurrentThread (java_vm, (void **)&env, NULL) != JNI_OK)
            return 0;
        attached = 1;
    } else if (status != JNI_OK) {
        return 0;
    }

    protected = (*env)->CallStaticBooleanMethod (
        env, tproxy_class, protect_socket_method, (jint)socket_fd);
    if ((*env)->ExceptionCheck (env)) {
        (*env)->ExceptionClear (env);
        protected = JNI_FALSE;
    }
    if (attached)
        (*java_vm)->DetachCurrentThread (java_vm);

    return protected == JNI_TRUE;
}

void
hev_jni_report_dns_event (const char *domain, int action,
                          uint32_t source_ipv4, uint16_t source_port)
{
    JNIEnv *env = NULL;
    char source_address[INET_ADDRSTRLEN] = "0.0.0.0";
    jstring java_domain;
    jstring java_source_address;
    int attached = 0;
    jint status;

    if (!java_vm || !tproxy_class || !dns_event_method)
        return;
    if (source_ipv4)
        inet_ntop (AF_INET, &source_ipv4, source_address, sizeof (source_address));

    status = (*java_vm)->GetEnv (java_vm, (void **)&env, JNI_VERSION_1_4);
    if (status == JNI_EDETACHED) {
        if ((*java_vm)->AttachCurrentThread (java_vm, (void **)&env, NULL) != JNI_OK)
            return;
        attached = 1;
    } else if (status != JNI_OK) {
        return;
    }

    java_domain = (*env)->NewStringUTF (env, domain);
    java_source_address = (*env)->NewStringUTF (env, source_address);
    if (java_domain && java_source_address) {
        (*env)->CallStaticVoidMethod (env, tproxy_class, dns_event_method,
                                     java_domain, (jint)action,
                                     java_source_address, (jint)source_port);
        if ((*env)->ExceptionCheck (env))
            (*env)->ExceptionClear (env);
    }
    if (java_domain)
        (*env)->DeleteLocalRef (env, java_domain);
    if (java_source_address)
        (*env)->DeleteLocalRef (env, java_source_address);
    if (attached)
        (*java_vm)->DetachCurrentThread (java_vm);
}

static void *
thread_handler (void *data)
{
    ThreadData *tdata = data;

    hev_socks5_tunnel_main (tdata->path, tdata->fd);

    atomic_store_explicit (&is_running, 0, memory_order_release);

    free (tdata->path);
    free (tdata);

    return NULL;
}

static jboolean
native_start_service (JNIEnv *env, jobject thiz, jstring config_path, jint fd)
{
    const jbyte *bytes;
    ThreadData *tdata;
    int res;
    jboolean result = JNI_FALSE;

    pthread_mutex_lock (&mutex);

    if (atomic_load_explicit (&is_running, memory_order_acquire))
        goto exit;

    if (thread_joinable) {
        pthread_join (work_thread, NULL);
        thread_joinable = 0;
    }

    tdata = malloc (sizeof (ThreadData));
    if (!tdata)
        goto exit;
    tdata->fd = fd;

    bytes = (const jbyte *)(*env)->GetStringUTFChars (env, config_path, NULL);
    if (!bytes) {
        free (tdata);
        goto exit;
    }
    tdata->path = strdup ((const char *)bytes);
    (*env)->ReleaseStringUTFChars (env, config_path, (const char *)bytes);
    if (!tdata->path) {
        free (tdata);
        goto exit;
    }

    atomic_store_explicit (&is_running, 1, memory_order_release);
    res = pthread_create (&work_thread, NULL, thread_handler, tdata);
    if (res != 0) {
        atomic_store_explicit (&is_running, 0, memory_order_release);
        free (tdata->path);
        free (tdata);
        goto exit;
    }

    thread_joinable = 1;
    result = JNI_TRUE;
exit:
    pthread_mutex_unlock (&mutex);
    return result;
}

static jboolean
native_stop_service (JNIEnv *env, jobject thiz)
{
    int res = 0;

    pthread_mutex_lock (&mutex);

    if (!thread_joinable)
        goto exit;

    if (atomic_load_explicit (&is_running, memory_order_acquire))
        hev_socks5_tunnel_quit ();
    res = pthread_join (work_thread, NULL);

    thread_joinable = 0;
    atomic_store_explicit (&is_running, 0, memory_order_release);
exit:
    pthread_mutex_unlock (&mutex);
    return res == 0 ? JNI_TRUE : JNI_FALSE;
}

static jboolean
native_is_running (JNIEnv *env, jobject thiz)
{
    return atomic_load_explicit (&is_running, memory_order_acquire) ? JNI_TRUE :
                                                                      JNI_FALSE;
}

static jlongArray
native_get_stats (JNIEnv *env, jobject thiz)
{
    size_t tx_packets, rx_packets, tx_bytes, rx_bytes;
    jlongArray res;
    jlong array[4];

    hev_socks5_tunnel_stats (&tx_packets, &tx_bytes, &rx_packets, &rx_bytes);
    array[0] = tx_packets;
    array[1] = tx_bytes;
    array[2] = rx_packets;
    array[3] = rx_bytes;

    res = (*env)->NewLongArray (env, 4);
    (*env)->SetLongArrayRegion (env, res, 0, 4, array);

    return res;
}

static void
native_set_blocked_ips (JNIEnv *env, jobject thiz, jobjectArray addresses)
{
    const jsize input_count = (*env)->GetArrayLength (env, addresses);
    const size_t capacity = input_count > 8192 ? 8192 : (size_t)input_count;
    uint32_t *parsed = calloc (capacity, sizeof (uint32_t));
    size_t count = 0;
    jsize i;

    if (!parsed && capacity)
        return;

    for (i = 0; i < input_count && count < capacity; i++) {
        jstring value = (jstring)(*env)->GetObjectArrayElement (env, addresses, i);
        const char *text;
        struct in_addr address;

        if (!value)
            continue;
        text = (*env)->GetStringUTFChars (env, value, NULL);
        if (text) {
            if (inet_pton (AF_INET, text, &address) == 1)
                parsed[count++] = address.s_addr;
            (*env)->ReleaseStringUTFChars (env, value, text);
        }
        (*env)->DeleteLocalRef (env, value);
    }

    hev_socks5_tunnel_set_blocked_ipv4 (parsed, count);
    free (parsed);
}

static jboolean
native_block_domain (JNIEnv *env, jobject thiz, jstring domain)
{
    const char *value;
    int result;

    if (!domain)
        return JNI_FALSE;
    value = (*env)->GetStringUTFChars (env, domain, NULL);
    if (!value)
        return JNI_FALSE;
    result = hev_socks5_tunnel_block_domain (value);
    (*env)->ReleaseStringUTFChars (env, domain, value);
    return result > 0 ? JNI_TRUE : JNI_FALSE;
}

static void
native_add_dynamic_sni_rule (JNIEnv *env, jclass klass, jstring domain)
{
    const char *value;
    int result;

    (void)klass;
    if (!domain) {
        jclass exception_class = (*env)->FindClass (env, "java/lang/IllegalArgumentException");
        if (exception_class)
            (*env)->ThrowNew (env, exception_class, "SNI domain must not be null.");
        return;
    }

    value = (*env)->GetStringUTFChars (env, domain, NULL);
    if (!value)
        return;

    result = aura_add_dynamic_sni_rule (value);
    (*env)->ReleaseStringUTFChars (env, domain, value);
    if (result > 0)
        return;

    {
        const char *class_name = result < 0
                                     ? "java/lang/IllegalArgumentException"
                                     : "java/lang/IllegalStateException";
        const char *message = result < 0
                                  ? "Invalid SNI domain."
                                  : "Dynamic SNI rule capacity is exhausted.";
        jclass exception_class = (*env)->FindClass (env, class_name);
        if (exception_class)
            (*env)->ThrowNew (env, exception_class, message);
    }
}

JNIEXPORT jboolean JNICALL
Java_com_ciberdefensa_aura_MainActivity_addDnsBlockRuleNative (
    JNIEnv *env, jobject thiz, jstring domain)
{
    const char *value;
    int result;

    (void)thiz;
    if (!domain)
        return JNI_FALSE;

    value = (*env)->GetStringUTFChars (env, domain, NULL);
    if (!value)
        return JNI_FALSE;

    result = aura_add_dynamic_sni_rule (value);
    (*env)->ReleaseStringUTFChars (env, domain, value);
    return result > 0 ? JNI_TRUE : JNI_FALSE;
}

static jboolean
native_set_dynamic_sni_allowlist (JNIEnv *env, jobject thiz,
                                  jobjectArray domains)
{
    const jsize domain_count = domains
                                   ? (*env)->GetArrayLength (env, domains)
                                   : 0;
    const size_t capacity = (size_t)domain_count;
    char **parsed;
    size_t count = 0;
    jsize i;
    int result;

    (void)thiz;
    if (!domains) {
        jclass exception_class =
            (*env)->FindClass (env, "java/lang/IllegalArgumentException");
        if (exception_class)
            (*env)->ThrowNew (env, exception_class,
                              "Dynamic SNI allowlist must not be null.");
        return JNI_FALSE;
    }
    if (capacity > 1024) {
        jclass exception_class =
            (*env)->FindClass (env, "java/lang/IllegalArgumentException");
        if (exception_class)
            (*env)->ThrowNew (env, exception_class,
                              "Dynamic SNI allowlist exceeds 1024 domains.");
        return JNI_FALSE;
    }
    parsed = calloc (capacity ? capacity : 1, sizeof (*parsed));
    if (!parsed)
        return JNI_FALSE;
    for (i = 0; i < domain_count; i++) {
        jstring value =
            (jstring)(*env)->GetObjectArrayElement (env, domains, i);
        const char *text;
        size_t length;

        if (!value)
            goto invalid_domain;
        text = (*env)->GetStringUTFChars (env, value, NULL);
        if (!text) {
            (*env)->DeleteLocalRef (env, value);
            goto jni_failure;
        }
        length = strlen (text);
        if (!length || length > 253) {
            (*env)->ReleaseStringUTFChars (env, value, text);
            (*env)->DeleteLocalRef (env, value);
            goto invalid_domain;
        }
        parsed[count] = malloc (length + 1);
        if (!parsed[count]) {
            (*env)->ReleaseStringUTFChars (env, value, text);
            (*env)->DeleteLocalRef (env, value);
            goto allocation_failed;
        }
        memcpy (parsed[count], text, length + 1);
        count++;
        (*env)->ReleaseStringUTFChars (env, value, text);
        (*env)->DeleteLocalRef (env, value);
    }

    result = aura_set_dynamic_sni_allowlist (
        (const char *const *)parsed, count);
    for (i = 0; i < (jsize)count; i++)
        free (parsed[i]);
    free (parsed);
    return result > 0 ? JNI_TRUE : JNI_FALSE;

invalid_domain:
    for (i = 0; i < (jsize)count; i++)
        free (parsed[i]);
    free (parsed);
    {
        jclass exception_class =
            (*env)->FindClass (env, "java/lang/IllegalArgumentException");
        if (exception_class)
            (*env)->ThrowNew (env, exception_class,
                              "Dynamic SNI allowlist contains an invalid domain.");
    }
    return JNI_FALSE;

allocation_failed:
    for (i = 0; i < (jsize)count; i++)
        free (parsed[i]);
    free (parsed);
    {
        jclass exception_class =
            (*env)->FindClass (env, "java/lang/OutOfMemoryError");
        if (exception_class)
            (*env)->ThrowNew (env, exception_class,
                              "Could not allocate the dynamic SNI allowlist.");
    }
    return JNI_FALSE;

jni_failure:
    for (i = 0; i < (jsize)count; i++)
        free (parsed[i]);
    free (parsed);
    return JNI_FALSE;
}

#endif /* ANDROID */
