/* Provide SSL/TLS functions to ESP32 with Arduino IDE
*
* Adapted from the ssl_client example of mbedtls.
*
* Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved, Apache 2.0 License.
* Additions Copyright (C) 2017 Evandro Luis Copercini, Apache 2.0 License.
* Additions Copyright (C) 2019 Vadim Govorovski.
* Additions Copyright (C) 2023 Maximiliano Ramirez.
*/

#include "Arduino.h"
#include <mbedtls/sha256.h>
#include <mbedtls/oid.h>
#include <algorithm>
#include <string>
#include <esp_task_wdt.h>
#include "ssl_lib_client.h"
#include "ssl_lib_crt_bundle.h"

namespace SSLClientLib {

#if !defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) && !defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#  warning "Please call `idf.py menuconfig` then go to Component config -> mbedTLS -> TLS Key Exchange Methods -> Enable pre-shared-key ciphersuites and then check `Enable PSK based cyphersuite modes`. Save and Quit."
#else

const char *pers = "esp32-tls";

static int _handle_error(int err, const char * function, int line)
{
    if(err == -30848){
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    log_e("[%s():%d]: (%d) %s", function, line, err, error_buf);
#else
    log_e("[%s():%d]: code %d", function, line, err);
#endif
    return err;
}

#define handle_error(e) _handle_error(e, __FUNCTION__, __LINE__)

/**
 * \brief          Read at most 'len' characters. If no error occurs,
 *                 the actual amount read is returned.
 *
 * \param ctx      Client*
 * \param buf      The buffer to write to
 * \param len      Maximum length of the buffer
 *
 * \return         the number of bytes received,
 *                 or a non-zero error code; with a non-blocking socket,
 *                 MBEDTLS_ERR_SSL_WANT_READ indicates read() would block.
 */
static int client_net_recv( void *ctx, unsigned char *buf, size_t len ) {
    Client *client = (Client*)ctx;
    if (!client) { 
        log_e("Uninitialised!");
        return -1;
    }
    
    //if (!client->connected()) {
    //    log_e("Not connected!");
    //    return -2;
   // }

    int result = client->read(buf, len);
    // log_d("SSL client RX res=%d len=%d", result, len);

    // if (result > 0) {
        //esp_log_buffer_hexdump_internal("SSL.RD", buf, (uint16_t)result, ESP_LOG_VERBOSE);
    // }
    
    return result;
}

int client_net_recv_timeout( void *ctx, unsigned char *buf,
                             size_t len, uint32_t timeout ) {
    Client *client = (Client*)ctx;
    if (!client) { 
        log_e("Uninitialised!");
        return -1;
    }
    unsigned long start = millis();
    unsigned long tms = start + timeout;
    do {
        int pending = client->available();
        if (pending < len && timeout > 0) {
            delay(1);
        } else break;
    } while (millis() < tms);
    
    int result = client->read(buf, len);
    
    if (!result) return MBEDTLS_ERR_SSL_WANT_READ;

    // log_d("SSL client RX (received=%d expected=%d in %dms)", result, len, millis()-start);

    // if (result > 0) {
        //esp_log_buffer_hexdump_internal("SSL.RD", buf, (uint16_t)result, ESP_LOG_VERBOSE);
    // }
    
    return result;
}


/**
 * \brief          Write at most 'len' characters. If no error occurs,
 *                 the actual amount read is returned.
 *
 * \param ctx      Client*
 * \param buf      The buffer to read from
 * \param len      The length of the buffer
 *
 * \return         the number of bytes sent,
 *                 or a non-zero error code; with a non-blocking socket,
 *                 MBEDTLS_ERR_SSL_WANT_WRITE indicates write() would block.
 */
static int client_net_send( void *ctx, const unsigned char *buf, size_t len ) {
    Client *client = (Client*)ctx;
    if (!client) { 
        log_e("Uninitialised!");
        return -1;
    }
    
    //if (!client->connected()) {
    //    log_e("Not connected!");
    //    return -2;
    //}
    
    //esp_log_buffer_hexdump_internal("SSL.WR", buf, (uint16_t)len, ESP_LOG_VERBOSE);
    
    int result = client->write(buf, len);
    
    // log_d("SSL client TX res=%d len=%d", result, len);
    return result;
}

void ssl_init(sslclient_context *ssl_client, Client *client)
{
    log_v("Init SSL");
    
    // [FIX] Persistent Memory Strategy
    // If already initialized, just update client pointer and return
    // Safe to check context_allocated since memory is calloc'd (zeroed) on allocation
    if (ssl_client->context_allocated) {
        ssl_client->client = client;
        return;
    }

    // Zero-out for clean initialization (redundant if calloc'd, but safe)
    memset(ssl_client, 0, sizeof(sslclient_context));
    ssl_client->client = client;
    
    // Initialize mbedTLS structures ONCE
    mbedtls_ssl_init(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_init(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_init(&ssl_client->drbg_ctx);
    mbedtls_entropy_init(&ssl_client->entropy_ctx);
    
    // Initialize certificate structures
    mbedtls_x509_crt_init(&ssl_client->ca_cert);
    mbedtls_x509_crt_init(&ssl_client->client_cert);
    mbedtls_pk_init(&ssl_client->client_key);
    
    // Mark as allocated so we never malloc/free again
    ssl_client->context_allocated = true;
}

int start_ssl_client(sslclient_context *ssl_client, const char *host, uint32_t port, int timeout, const char *rootCABuff, bool useRootCABundle, const char *cli_cert, const char *cli_key, const char *pskIdent, const char *psKey, bool insecure, const char **alpn_protos)
{
    char buf[512];
    int ret, flags;
    //int enable = 1;
    log_v("Free internal heap before TLS %u", ESP.getFreeHeap());

    log_i("Connecting to %s:%d", host, port);

    Client *pClient = ssl_client->client;

    if (!pClient) {
        log_e("Client provider not initialised");
        return -1;
    }

    if (!pClient->connect(host, port)) {
        log_e("Connect to Server failed!");
        return -2;
    }

    // [FIX] Only seed RNG on first connection (persistent context reuses same DRBG)
    if (!ssl_client->drbg_seeded) {
        log_v("Seeding the random number generator");
        ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                    &ssl_client->entropy_ctx, (const unsigned char *) pers, strlen(pers));
        if (ret < 0) {
            return handle_error(ret);
        }
        ssl_client->drbg_seeded = true;
    } else {
        // Subsequent connections: DRBG is already seeded and maintains its own state
        log_v("Reusing seeded random number generator");
    }

    log_v("Setting up the SSL/TLS structure...");

    // [FIX] Only set config defaults on first connection (persistent config reuse)
    if (!ssl_client->config_setup) {
        if ((ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf,
                                               MBEDTLS_SSL_IS_CLIENT,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            return handle_error(ret);
        }
        ssl_client->config_setup = true;
    }

    // [FIX] REDUCE MEMORY USAGE
    // Force mbedTLS to use 4KB buffers instead of default 16KB.
    // This prevents allocation failures when heap is fragmented (10000s issue).
    // AWS IoT supports this extension.
    #ifdef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    if ((ret = mbedtls_ssl_conf_max_frag_len(&ssl_client->ssl_conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096)) != 0) {
        log_e("Failed to set Max Fragment Length to 4096");
        return handle_error(ret);
    }
    #endif

    if (alpn_protos != NULL) {
        log_v("Setting ALPN protocols");
        if ((ret = mbedtls_ssl_conf_alpn_protocols(&ssl_client->ssl_conf, alpn_protos) ) != 0) {
            return handle_error(ret);
        }
    }

    // MBEDTLS_SSL_VERIFY_REQUIRED if a CA certificate is defined on Arduino IDE and
    // MBEDTLS_SSL_VERIFY_NONE if not.

    if (insecure) {
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        log_d("WARNING: Skipping SSL Verification. INSECURE!");
    } else if (rootCABuff != NULL) {
        log_v("Loading CA cert");
        // [FIX] Don't re-init, already initialized in stop_ssl_socket or ssl_init
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);
        mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);
        //mbedtls_ssl_conf_verify(&ssl_client->ssl_ctx, my_verify, NULL );
        if (ret < 0) {
            // free the ca_cert in the case parse failed, otherwise, the old ca_cert still in the heap memory, that lead to "out of memory" crash.
            mbedtls_x509_crt_free(&ssl_client->ca_cert);
            return handle_error(ret);
        }
    } else if (useRootCABundle) {
        log_v("Attaching root CA cert bundle");
        ret = ssl_lib_crt_bundle_attach(&ssl_client->ssl_conf);

        if (ret < 0) {
            return handle_error(ret);
        }
    } else if (pskIdent != NULL && psKey != NULL) {
        log_v("Setting up PSK");
        // convert PSK from hex to binary
        if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2*MBEDTLS_PSK_MAX_LEN) {
            log_e("pre-shared key not valid hex or too long");
            return -1;
        }
        unsigned char psk[MBEDTLS_PSK_MAX_LEN];
        size_t psk_len = strlen(psKey)/2;
        for (int j=0; j<strlen(psKey); j+= 2) {
            char c = psKey[j];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] = c<<4;
            c = psKey[j+1];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] |= c;
        }
        // set mbedtls config
        ret = mbedtls_ssl_conf_psk(&ssl_client->ssl_conf, psk, psk_len,
                 (const unsigned char *)pskIdent, strlen(pskIdent));
        if (ret != 0) {
            log_e("mbedtls_ssl_conf_psk returned %d", ret);
            return handle_error(ret);
        }
    } else {
        return -1;
    }

    if (!insecure && cli_cert != NULL && cli_key != NULL) {
        // [FIX] Don't re-init, already initialized in stop_ssl_socket or ssl_init

        log_v("Loading CRT cert");

        ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
        if (ret < 0) {
            // free the client_cert in the case parse failed, otherwise, the old client_cert still in the heap memory, that lead to "out of memory" crash.
            mbedtls_x509_crt_free(&ssl_client->client_cert);
            return handle_error(ret);
        }

        log_v("Loading private key");
        ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);

        if (ret != 0) {
            mbedtls_x509_crt_free(&ssl_client->client_cert); // cert+key are free'd in pair
            return handle_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
    }

    log_v("Setting hostname for TLS session...");

    // Hostname set here should match CN in server certificate
    if((ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, host)) != 0){
        return handle_error(ret);
	}

    mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);

    if ((ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf)) != 0) {
        return handle_error(ret);
    }

    log_v("Setting up IO callbacks...");
    mbedtls_ssl_set_bio(&ssl_client->ssl_ctx, ssl_client->client, client_net_send, NULL, client_net_recv_timeout);

    log_v("Performing the SSL/TLS handshake...");
    unsigned long handshake_start_time=millis();
    while ((ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return handle_error(ret);
        }
        if((millis()-handshake_start_time)>ssl_client->handshake_timeout)
			return -1;
	    vTaskDelay(2);//2 ticks
    }


    if (cli_cert != NULL && cli_key != NULL) {
        log_d("Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
        if ((ret = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx)) >= 0) {
            log_d("Record expansion is %d", ret);
        } else {
            log_w("Record expansion is unknown (compression)");
        }
    }

    log_v("Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx)) != 0) {
        memset(buf, 0, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        log_e("Failed to verify peer certificate! verification info: %s", buf);
        return handle_error(ret);
    } else {
        log_v("Certificate verified.");
    }
    
    if (rootCABuff != NULL) {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }

    if (cli_cert != NULL) {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
    }

    if (cli_key != NULL) {
        mbedtls_pk_free(&ssl_client->client_key);
    }    

    log_v("Free internal heap after TLS %u", ESP.getFreeHeap());

    //return ssl_client->socket;
    return 1;
}


void stop_ssl_socket(sslclient_context *ssl_client, const char *rootCABuff, const char *cli_cert, const char *cli_key)
{
    log_v("Cleaning SSL connection (Persistent Mode).");

    // [CRITICAL FIX] DO NOT call client->stop() here!
    // The caller (SSLClientESP32::stop) should decide whether to stop the underlying client.
    // When SSL detects a dead connection (write returns 0), the client is already dead.
    // Calling stop() on TinyGSM sends AT+CIPCLOSE which blocks 15s on dead connections.
    // This causes the watchdog timeout at 10000s uptime.
    // The client will be cleaned up on next reconnection attempt.

    // [FIX] DO NOT FREE MEMORY. JUST RESET SESSION AND CERTIFICATES.
    // This prevents the Heap Fragmentation hole-punching effect.
    
    // First, clear the certificate pointers from config to avoid dangling references
    // (mbedtls_ssl_conf_ca_chain and mbedtls_ssl_conf_own_cert set these)
    ssl_client->ssl_conf.ca_chain = NULL;
    ssl_client->ssl_conf.key_cert = NULL;
    
    // Now free and re-init the certificate structures themselves
    mbedtls_x509_crt_free(&ssl_client->ca_cert);
    mbedtls_x509_crt_init(&ssl_client->ca_cert);
    
    mbedtls_x509_crt_free(&ssl_client->client_cert);
    mbedtls_x509_crt_init(&ssl_client->client_cert);
    
    mbedtls_pk_free(&ssl_client->client_key);
    mbedtls_pk_init(&ssl_client->client_key);
    
    // Reset the SSL session state for the next connection
    // This clears session-specific data but keeps the SSL context allocated
    mbedtls_ssl_session_reset(&ssl_client->ssl_ctx);

    // CRITICAL: Do NOT call mbedtls_ssl_free, config_free, drbg_free, or entropy_free.
    // We keep the heavy allocations alive for the next round to prevent fragmentation.
}


int data_to_read(sslclient_context *ssl_client)
{
    int ret, res;
    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, NULL, 0);
    //log_e("RET: %i",ret);   //for low level debug
    res = mbedtls_ssl_get_bytes_avail(&ssl_client->ssl_ctx);
    //log_e("RES: %i",res);    //for low level debug
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        return handle_error(ret);
    }

    return res;
}

int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len)
{
    log_d("Writing SSL (%d bytes)...", len);
    int ret = -1;

    unsigned long start = millis();
    unsigned long sendTimeout = 10000; 

    while ((ret = mbedtls_ssl_write(&ssl_client->ssl_ctx, data, len)) <= 0) {
        
        // The check that catches the 2.7h bug
        if (ret == 0) {
            log_e("SSL Write returned 0 (Connection Closed/Stalled)");
            return -1; 
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
            log_v("Handling error %d", ret);
            return handle_error(ret);
        }

        if (millis() - start > sendTimeout) {
            log_e("SSL Write Timed Out (>10s) - Force Close");
            return -1;
        }

        esp_task_wdt_reset();
        vTaskDelay(10); 
    }

    return ret;
}

int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length)
{
    // log_d( "Reading SSL (%d bytes)", length);   //for low level debug
    int ret = -1;

    ret = mbedtls_ssl_read(&ssl_client->ssl_ctx, data, length);

    // log_v( "%d bytes read", ret);   //for low level debug
    return ret;
}

static bool parseHexNibble(char pb, uint8_t* res)
{
    if (pb >= '0' && pb <= '9') {
        *res = (uint8_t) (pb - '0'); return true;
    } else if (pb >= 'a' && pb <= 'f') {
        *res = (uint8_t) (pb - 'a' + 10); return true;
    } else if (pb >= 'A' && pb <= 'F') {
        *res = (uint8_t) (pb - 'A' + 10); return true;
    }
    return false;
}

// Compare a name from certificate and domain name, return true if they match
static bool matchName(const std::string& name, const std::string& domainName)
{
    size_t wildcardPos = name.find('*');
    if (wildcardPos == std::string::npos) {
        // Not a wildcard, expect an exact match
        return name == domainName;
    }

    size_t firstDotPos = name.find('.');
    if (wildcardPos > firstDotPos) {
        // Wildcard is not part of leftmost component of domain name
        // Do not attempt to match (rfc6125 6.4.3.1)
        return false;
    }
    if (wildcardPos != 0 || firstDotPos != 1) {
        // Matching of wildcards such as baz*.example.com and b*z.example.com
        // is optional. Maybe implement this in the future?
        return false;
    }
    size_t domainNameFirstDotPos = domainName.find('.');
    if (domainNameFirstDotPos == std::string::npos) {
        return false;
    }
    return domainName.substr(domainNameFirstDotPos) == name.substr(firstDotPos);
}

// Verifies certificate provided by the peer to match specified SHA256 fingerprint
bool verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name)
{
    // Convert hex string to byte array
    uint8_t fingerprint_local[32];
    int len = strlen(fp);
    int pos = 0;
    for (size_t i = 0; i < sizeof(fingerprint_local); ++i) {
        while (pos < len && ((fp[pos] == ' ') || (fp[pos] == ':'))) {
            ++pos;
        }
        if (pos > len - 2) {
            log_d("pos:%d len:%d fingerprint too short", pos, len);
            return false;
        }
        uint8_t high, low;
        if (!parseHexNibble(fp[pos], &high) || !parseHexNibble(fp[pos+1], &low)) {
            log_d("pos:%d len:%d invalid hex sequence: %c%c", pos, len, fp[pos], fp[pos+1]);
            return false;
        }
        pos += 2;
        fingerprint_local[i] = low | (high << 4);
    }

    // Calculate certificate's SHA256 fingerprint
    uint8_t fingerprint_remote[32];
    if(!get_peer_fingerprint(ssl_client, fingerprint_remote)) 
        return false;

    // Check if fingerprints match
    if (memcmp(fingerprint_local, fingerprint_remote, 32))
    {
        log_d("fingerprint doesn't match");
        return false;
    }

    // Additionally check if certificate has domain name if provided
    if (domain_name)
        return verify_ssl_dn(ssl_client, domain_name);
    else
        return true;
}

bool get_peer_fingerprint(sslclient_context *ssl_client, uint8_t sha256[32]) 
{
    if (!ssl_client) {
        log_d("Invalid ssl_client pointer");
        return false;
    };

    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);
    if (!crt) {
        log_d("Failed to get peer cert.");
        return false;
    };

    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, false);
    mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
    mbedtls_sha256_finish(&sha256_ctx, sha256);
    
    // [FIX] MEMORY LEAK FIX
    // The original library forgot to free the context
    mbedtls_sha256_free(&sha256_ctx); 

    return true;
}

// Checks if peer certificate has specified domain in CN or SANs
bool verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name)
{
    log_d("domain name: '%s'", (domain_name)?domain_name:"(null)");
    std::string domain_name_str(domain_name);
    std::transform(domain_name_str.begin(), domain_name_str.end(), domain_name_str.begin(), ::tolower);

    // Get certificate provided by the peer
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);

    // Check for domain name in SANs
    const mbedtls_x509_sequence* san = &crt->subject_alt_names;
    while (san != nullptr)
    {
        std::string san_str((const char*)san->buf.p, san->buf.len);
        std::transform(san_str.begin(), san_str.end(), san_str.begin(), ::tolower);

        if (matchName(san_str, domain_name_str))
            return true;

        log_d("SAN '%s': no match", san_str.c_str());

        // Fetch next SAN
        san = san->next;
    }

    // Check for domain name in CN
    const mbedtls_asn1_named_data* common_name = &crt->subject;
    while (common_name != nullptr)
    {
        // While iterating through DN objects, check for CN object
        if (!MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &common_name->oid))
        {
            std::string common_name_str((const char*)common_name->val.p, common_name->val.len);

            if (matchName(common_name_str, domain_name_str))
                return true;

            log_d("CN '%s': not match", common_name_str.c_str());
        }

        // Fetch next DN object
        common_name = common_name->next;
    }

    return false;
}
#endif

}