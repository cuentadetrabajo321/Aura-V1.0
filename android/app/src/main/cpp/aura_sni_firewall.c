#include "aura_sni_firewall.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define AURA_MAX_DYNAMIC_SNI_RULES 1024
#define AURA_MAX_DOMAIN_LENGTH 253
#define AURA_MAX_TLS_RECORD_LENGTH 18432
#define AURA_MAX_CLIENT_HELLO_LENGTH 65535

static char dynamic_sni_rules[AURA_MAX_DYNAMIC_SNI_RULES]
                             [AURA_MAX_DOMAIN_LENGTH + 1];
static size_t dynamic_sni_rules_count;
static char dynamic_sni_allowlist[AURA_MAX_DYNAMIC_SNI_RULES]
                                 [AURA_MAX_DOMAIN_LENGTH + 1];
static size_t dynamic_sni_allowlist_count;
static pthread_mutex_t dynamic_sni_rules_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint16_t
read_u16 (const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static int
handshake_bytes_available (const uint8_t *payload, size_t payload_len,
                           size_t required_length)
{
    size_t record_offset = 0;
    size_t stream_length = 0;

    while (stream_length < required_length) {
        size_t record_length;
        size_t available_length;

        if (payload_len - record_offset < 5)
            return 0;
        if (payload[record_offset] != 0x16 ||
            payload[record_offset + 1] != 0x03)
            return -1;

        record_length = read_u16 (payload + record_offset + 3);
        if (!record_length || record_length > AURA_MAX_TLS_RECORD_LENGTH)
            return -1;

        available_length = payload_len - record_offset - 5;
        if (available_length > record_length)
            available_length = record_length;
        if (available_length >= required_length - stream_length)
            return 1;

        stream_length += available_length;
        if (available_length < record_length)
            return 0;
        record_offset += 5 + record_length;
    }

    return 1;
}

static int
normalize_domain (const uint8_t *domain, size_t length, char *normalized)
{
    size_t i;
    size_t label_length = 0;

    if (!domain || !normalized || !length || length > AURA_MAX_DOMAIN_LENGTH)
        return -1;

    for (i = 0; i < length; i++) {
        const uint8_t ch = domain[i];

        if (ch == '.') {
            if (!label_length || normalized[i - 1] == '-')
                return -1;
            normalized[i] = '.';
            label_length = 0;
        } else if ((ch >= 'a' && ch <= 'z') ||
                   (ch >= 'A' && ch <= 'Z') ||
                   (ch >= '0' && ch <= '9') || ch == '-') {
            if (!label_length && ch == '-')
                return -1;
            normalized[i] = ch >= 'A' && ch <= 'Z'
                                ? (char)(ch + ('a' - 'A'))
                                : (char)ch;
            if (++label_length > 63)
                return -1;
        } else {
            return -1;
        }
    }

    if (!label_length || normalized[length - 1] == '-')
        return -1;

    normalized[length] = '\0';
    return 0;
}

static int
domain_matches_rule (const char *domain, const char *rule)
{
    const size_t domain_length = strlen (domain);
    const size_t rule_length = strlen (rule);
    const size_t domain_offset =
        domain_length >= rule_length ? domain_length - rule_length : 0;
    size_t i;

    if (domain_length < rule_length)
        return 0;

    for (i = 0; i < rule_length; i++) {
        char ch = domain[domain_offset + i];
        if (ch >= 'A' && ch <= 'Z')
            ch = (char)(ch + ('a' - 'A'));
        if (ch != rule[i])
            return 0;
    }

    return domain_offset == 0 || domain[domain_offset - 1] == '.';
}

static int
domain_is_blocked (const char *domain)
{
    size_t i;

    pthread_mutex_lock (&dynamic_sni_rules_mutex);
    for (i = 0; i < dynamic_sni_allowlist_count; i++) {
        if (domain_matches_rule (domain, dynamic_sni_allowlist[i])) {
            pthread_mutex_unlock (&dynamic_sni_rules_mutex);
            return 0;
        }
    }
    for (i = 0; i < dynamic_sni_rules_count; i++) {
        if (domain_matches_rule (domain, dynamic_sni_rules[i])) {
            pthread_mutex_unlock (&dynamic_sni_rules_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock (&dynamic_sni_rules_mutex);

    return 0;
}

static int
copy_handshake_bytes (const uint8_t *payload, size_t payload_len,
                      size_t handshake_offset, uint8_t *output,
                      size_t output_len)
{
    size_t record_offset = 0;
    size_t stream_offset = 0;
    size_t copied = 0;

    while (copied < output_len) {
        size_t record_length;
        size_t available_length;
        size_t skip;
        size_t copy_length;

        if (payload_len - record_offset < 5)
            return 0;
        if (payload[record_offset] != 0x16 ||
            payload[record_offset + 1] != 0x03)
            return -1;

        record_length = read_u16 (payload + record_offset + 3);
        if (!record_length || record_length > AURA_MAX_TLS_RECORD_LENGTH)
            return -1;

        available_length = payload_len - record_offset - 5;
        if (available_length > record_length)
            available_length = record_length;

        skip = handshake_offset > stream_offset
                   ? handshake_offset - stream_offset
                   : 0;
        if (skip < available_length) {
            copy_length = available_length - skip;
            if (copy_length > output_len - copied)
                copy_length = output_len - copied;
            memcpy (output + copied, payload + record_offset + 5 + skip,
                    copy_length);
            copied += copy_length;
            handshake_offset += copy_length;
        }

        if (copied == output_len)
            return 1;

        if (available_length < record_length)
            return 0;

        stream_offset += record_length;
        record_offset += 5 + record_length;
    }

    return 1;
}

static AuraTlsSniResult
inspect_client_hello (const uint8_t *hello, size_t hello_length, char *sni,
                      size_t sni_capacity)
{
    size_t cursor = 4;
    size_t body_end = hello_length;
    size_t session_id_length;
    size_t cipher_suites_length;
    size_t compression_methods_length;
    size_t extensions_length;
    size_t extensions_end;

    if (hello_length < 4 || hello[0] != 0x01)
        return AURA_TLS_SNI_MALFORMED;
    if (cursor + 34 > body_end)
        return AURA_TLS_SNI_MALFORMED;
    cursor += 34;

    if (cursor >= body_end)
        return AURA_TLS_SNI_MALFORMED;
    session_id_length = hello[cursor++];
    if (session_id_length > 32 || session_id_length > body_end - cursor)
        return AURA_TLS_SNI_MALFORMED;
    cursor += session_id_length;

    if (body_end - cursor < 2)
        return AURA_TLS_SNI_MALFORMED;
    cipher_suites_length = read_u16 (hello + cursor);
    cursor += 2;
    if (cipher_suites_length < 2 || (cipher_suites_length & 1) ||
        cipher_suites_length > body_end - cursor)
        return AURA_TLS_SNI_MALFORMED;
    cursor += cipher_suites_length;

    if (cursor >= body_end)
        return AURA_TLS_SNI_MALFORMED;
    compression_methods_length = hello[cursor++];
    if (!compression_methods_length ||
        compression_methods_length > body_end - cursor)
        return AURA_TLS_SNI_MALFORMED;
    cursor += compression_methods_length;

    if (cursor == body_end)
        return AURA_TLS_SNI_ALLOWED;
    if (body_end - cursor < 2)
        return AURA_TLS_SNI_MALFORMED;
    extensions_length = read_u16 (hello + cursor);
    cursor += 2;
    if (extensions_length != body_end - cursor)
        return AURA_TLS_SNI_MALFORMED;
    extensions_end = cursor + extensions_length;

    while (extensions_end - cursor >= 4) {
        const uint16_t extension_type = read_u16 (hello + cursor);
        const size_t extension_length = read_u16 (hello + cursor + 2);
        size_t extension_end;

        cursor += 4;
        if (extension_length > extensions_end - cursor)
            return AURA_TLS_SNI_MALFORMED;
        extension_end = cursor + extension_length;

        if (extension_type == 0x0000) {
            size_t name_cursor;
            size_t name_list_length;

            if (extension_length < 2)
                return AURA_TLS_SNI_MALFORMED;
            name_list_length = read_u16 (hello + cursor);
            name_cursor = cursor + 2;
            if (name_list_length != extension_end - name_cursor)
                return AURA_TLS_SNI_MALFORMED;

            while (name_cursor < extension_end) {
                const uint8_t name_type = hello[name_cursor++];
                size_t name_length;
                char normalized[AURA_MAX_DOMAIN_LENGTH + 1];

                if (extension_end - name_cursor < 2)
                    return AURA_TLS_SNI_MALFORMED;
                name_length = read_u16 (hello + name_cursor);
                name_cursor += 2;
                if (!name_length || name_length > extension_end - name_cursor)
                    return AURA_TLS_SNI_MALFORMED;

                if (name_type == 0) {
                    if (normalize_domain (hello + name_cursor, name_length,
                                          normalized) < 0)
                        return AURA_TLS_SNI_MALFORMED;
                    if (sni && sni_capacity) {
                        const size_t copy_length =
                            name_length < sni_capacity - 1
                                ? name_length
                                : sni_capacity - 1;
                        memcpy (sni, normalized, copy_length);
                        sni[copy_length] = '\0';
                    }
                    if (domain_is_blocked (normalized))
                        return AURA_TLS_SNI_BLOCKED;
                }

                name_cursor += name_length;
            }
        }

        cursor = extension_end;
    }

    if (cursor != extensions_end)
        return AURA_TLS_SNI_MALFORMED;

    return AURA_TLS_SNI_ALLOWED;
}

AuraTlsSniResult
aura_inspect_tls_sni (const uint8_t *payload, uint32_t payload_len, char *sni,
                      size_t sni_capacity)
{
    uint8_t handshake_header[4];
    uint8_t *hello;
    uint32_t handshake_length;
    size_t hello_length;
    int copied;
    AuraTlsSniResult result;

    if (sni && sni_capacity)
        sni[0] = '\0';
    if (!payload && payload_len)
        return AURA_TLS_SNI_MALFORMED;
    if (!payload_len)
        return AURA_TLS_SNI_INCOMPLETE;
    if (payload[0] != 0x16)
        return AURA_TLS_SNI_ALLOWED;
    if (payload_len < 5)
        return AURA_TLS_SNI_INCOMPLETE;
    if (payload[1] != 0x03)
        return AURA_TLS_SNI_MALFORMED;

    copied = copy_handshake_bytes (payload, payload_len, 0, handshake_header,
                                   sizeof (handshake_header));
    if (copied == 0)
        return AURA_TLS_SNI_INCOMPLETE;
    if (copied < 0)
        return AURA_TLS_SNI_MALFORMED;
    if (handshake_header[0] != 0x01)
        return AURA_TLS_SNI_ALLOWED;

    handshake_length = ((uint32_t)handshake_header[1] << 16) |
                       ((uint32_t)handshake_header[2] << 8) |
                       handshake_header[3];
    if (handshake_length > AURA_MAX_CLIENT_HELLO_LENGTH - 4)
        return AURA_TLS_SNI_MALFORMED;
    hello_length = (size_t)handshake_length + 4;
    copied = handshake_bytes_available (payload, payload_len, hello_length);
    if (copied == 0)
        return AURA_TLS_SNI_INCOMPLETE;
    if (copied < 0)
        return AURA_TLS_SNI_MALFORMED;

    hello = malloc (hello_length);
    if (!hello)
        return AURA_TLS_SNI_MALFORMED;

    copied = copy_handshake_bytes (payload, payload_len, 0, hello,
                                   hello_length);
    if (copied == 0) {
        free (hello);
        return AURA_TLS_SNI_INCOMPLETE;
    }
    if (copied < 0) {
        free (hello);
        return AURA_TLS_SNI_MALFORMED;
    }

    result = inspect_client_hello (hello, hello_length, sni, sni_capacity);
    free (hello);
    return result;
}

bool
aura_should_block_tls_sni (const uint8_t *payload, uint32_t payload_len)
{
    const AuraTlsSniResult result =
        aura_inspect_tls_sni (payload, payload_len, NULL, 0);

    return result == AURA_TLS_SNI_BLOCKED ||
           result == AURA_TLS_SNI_MALFORMED;
}

int
aura_add_dynamic_sni_rule (const char *domain)
{
    char normalized[AURA_MAX_DOMAIN_LENGTH + 1];
    size_t length;
    size_t i;

    if (!domain)
        return -1;
    length = strlen (domain);
    if (normalize_domain ((const uint8_t *)domain, length, normalized) < 0)
        return -1;

    pthread_mutex_lock (&dynamic_sni_rules_mutex);
    for (i = 0; i < dynamic_sni_rules_count; i++) {
        if (strcmp (dynamic_sni_rules[i], normalized) == 0) {
            pthread_mutex_unlock (&dynamic_sni_rules_mutex);
            return 1;
        }
    }
    if (dynamic_sni_rules_count == AURA_MAX_DYNAMIC_SNI_RULES) {
        pthread_mutex_unlock (&dynamic_sni_rules_mutex);
        return 0;
    }

    memcpy (dynamic_sni_rules[dynamic_sni_rules_count++], normalized,
            length + 1);
    pthread_mutex_unlock (&dynamic_sni_rules_mutex);
    return 1;
}

int
aura_set_dynamic_sni_allowlist (const char *const *domains, size_t count)
{
    char (*normalized_domains)[AURA_MAX_DOMAIN_LENGTH + 1];
    size_t normalized_count = 0;
    size_t i;

    if (count > AURA_MAX_DYNAMIC_SNI_RULES || (count && !domains))
        return 0;
    normalized_domains = calloc (count ? count : 1,
                                 sizeof (*normalized_domains));
    if (!normalized_domains)
        return 0;

    for (i = 0; i < count; i++) {
        size_t length;
        size_t j;
        char normalized[AURA_MAX_DOMAIN_LENGTH + 1];

        if (!domains[i]) {
            free (normalized_domains);
            return -1;
        }
        length = strlen (domains[i]);
        if (normalize_domain ((const uint8_t *)domains[i], length,
                              normalized) < 0) {
            free (normalized_domains);
            return -1;
        }

        for (j = 0; j < normalized_count; j++) {
            if (strcmp (normalized_domains[j], normalized) == 0)
                break;
        }
        if (j == normalized_count) {
            memcpy (normalized_domains[normalized_count], normalized,
                    length + 1);
            normalized_count++;
        }
    }

    pthread_mutex_lock (&dynamic_sni_rules_mutex);
    if (normalized_count)
        memcpy (dynamic_sni_allowlist, normalized_domains,
                normalized_count * sizeof (*normalized_domains));
    dynamic_sni_allowlist_count = normalized_count;
    pthread_mutex_unlock (&dynamic_sni_rules_mutex);

    free (normalized_domains);
    return 1;
}
