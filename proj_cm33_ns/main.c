/********************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2024-2025 TESA
 * All rights reserved.</center></h2>
 *
 * This source code and any compilation or derivative thereof is the
 * proprietary information of TESA and is confidential in nature.
 *
 ********************************************************************************
 * Project : OPTIGA Trust M Connectivity Tutorial Series
 ********************************************************************************
 * Module  : Part 3 - Secure Communication Channel Demo
 * Purpose : Demonstrate cryptographic building blocks for secure connectivity:
 *           device authentication using ECDSA signatures and AES-GCM
 *           encrypted messaging. This autonomous demo teaches the security
 *           primitives used in production IoT device-to-cloud systems.
 * Design  : See blog-03-secure-channel.md for detailed explanation
 ********************************************************************************
 * @file    main.c
 * @brief   Secure channel demo with TF-M integration
 * @author  TESA Workshop Team
 * @date    January 11, 2026
 * @version 1.0.0
 *
 * @note    Based on Infineon CE241509 - TF-M Crypto Application Example
 *          Enhanced to demonstrate production-like secure communication
 *
 * @see     https://github.com/TESA-Workshops/psoc-edge-optiga-03-secure-channel
 ********************************************************************************
 * Original Copyright Notice:
 * (c) 2024-2025, Infineon Technologies AG, or an affiliate of Infineon
 * Technologies AG.  SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

/* -------------------------------------------------------------------- */
/* Includes                                                             */
/* -------------------------------------------------------------------- */
/* --------------------   */
/* Standard Library       */
/* --------------------   */
#include <stdio.h>
#include <string.h>

/* --------------------   */
/* Infineon Libraries     */
/* --------------------   */
#include "cybsp.h"
#include "cy_pdl.h"
#include "ifx_platform_api.h"

/* --------------------   */
/* TF-M & PSA APIs        */
/* --------------------   */
#include "tfm_ns_interface.h"
#include "os_wrapper/common.h"
#include "psa/crypto.h"


/* -------------------------------------------------------------------- */
/* Macros                                                               */
/* -------------------------------------------------------------------- */

/** @brief ECDSA P-256 key size in bits */
#define EC_KEY_BITS                   ((size_t) 256)

/** @brief ECDSA signature size (R + S components, 32 bytes each) */
#define EC_SIGNATURE_SIZE             (2*(EC_KEY_BITS/8))

/** @brief EC public key size (uncompressed format: 0x04 + X + Y) */
#define EC_PUBLIC_KEY_SIZE            (1 + 2*(EC_KEY_BITS/8))

/** @brief ECDH shared secret size in bytes (P-256) */
#define ECDH_SHARED_SECRET_SIZE       (EC_KEY_BITS/8)

/** @brief AES-GCM key size in bits */
#define AES_KEY_SIZE                  ((size_t) 128)

/** @brief Buffer size for encrypted data (plaintext + auth tag) */
#define AES_BUFF_SIZE                 (64U)

/** @brief AES-GCM nonce (IV) size */
#define GCM_NONCE_SIZE                ((size_t) 12)

/** @brief AES-GCM authentication tag size */
#define GCM_TAG_SIZE                  ((size_t) 16)

/** @brief Number of bytes to print per line in hex dump */
#define PRNT_BYTES_PER_LINE           (16u)

/** @brief CM55 boot timeout in microseconds */
#define CM55_BOOT_WAIT_TIME_USEC      (10U)

/** @brief CM55 application boot address */
#define CM55_APP_BOOT_ADDR            (CYMEM_CM33_0_m55_nvm_START + \
                                        CYBSP_MCUBOOT_HEADER_SIZE)


/* -------------------------------------------------------------------- */
/* Global Variables                                                     */
/* -------------------------------------------------------------------- */
/* (None) */


/* -------------------------------------------------------------------- */
/* Function Prototypes                                                  */
/* -------------------------------------------------------------------- */
static void print_hex(const char* label, const uint8_t* data, size_t len, unsigned char* out_buf);


/* -------------------------------------------------------------------- */
/* Function Definitions                                                 */
/* -------------------------------------------------------------------- */

/**
 * @brief Helper function to print hex data with label
 *
 * @param label  Description label for the data
 * @param data   Pointer to data buffer
 * @param len    Length of data in bytes
 * @param out_buf Working buffer for formatting output
 */
static void print_hex(const char* label, const uint8_t* data, size_t len, unsigned char* out_buf)
{
    int buf_size;

    buf_size = sprintf((char*)out_buf, "%s", label);
    ifx_platform_log_msg(out_buf, buf_size);

    for(int i = 0; i < ((len/PRNT_BYTES_PER_LINE) + ((len%PRNT_BYTES_PER_LINE) ? 1: 0)); i++)
    {
        int j;
        for(j = 0; j < PRNT_BYTES_PER_LINE; j++)
        {
            if((i*PRNT_BYTES_PER_LINE + j) >= len)
            {
                break;
            }
            sprintf((char*)(out_buf + 5*j), "0x%02x ", data[(i*PRNT_BYTES_PER_LINE + j)]);
        }
        buf_size = sprintf((char*)(out_buf + 5*j), "\r\n");
        ifx_platform_log_msg(out_buf, ((j*5) + buf_size));
    }
}

/**
 * @brief Main function - Secure communication channel demo
 *
 * Demonstrates a complete secure communication flow:
 * 1. Handshake Phase: ECDH key exchange with mutual authentication
 * 2. Session Setup: Derive AES-GCM encryption key with HKDF
 * 3. Data Transfer: Encrypt and decrypt messages
 *
 * This demo simulates device-to-cloud connectivity where:
 * - Device authenticates with ECDSA signature
 * - Session keys are established via ECDH + HKDF
 * - Data is encrypted with AES-GCM
 *
 * Output format uses [HS] and [DATA] tags for easy parsing.
 *
 * @return int  Exit status (never returns in normal operation)
 *
 * @note This demo uses ephemeral keys for simplicity. Production systems
 *       should use OPTIGA persistent device keys for authentication.
 */
int main(void)
{
    cy_rslt_t result;
    uint32_t rslt;
    psa_status_t status;

    /* Key handles */
    psa_key_id_t device_key_id;       /* Device ECDSA key (simulates OPTIGA key) */
    psa_key_id_t device_ecdh_key_id;  /* Device ECDH key */
    psa_key_id_t cloud_ecdh_key_id;   /* Cloud ECDH key (simulated) */
    psa_key_id_t shared_secret_key_id;/* Shared secret key for HKDF */
    psa_key_id_t session_key_id;      /* AES-GCM session key */

    /* Handshake data */
    uint8_t device_public_key[EC_PUBLIC_KEY_SIZE];
    size_t device_pubkey_len;
    uint8_t device_nonce[16];
    uint8_t device_signature[EC_SIGNATURE_SIZE];
    size_t signature_len;
    uint8_t device_ecdh_pubkey[EC_PUBLIC_KEY_SIZE];
    size_t device_ecdh_pubkey_len;
    uint8_t cloud_ecdh_pubkey[EC_PUBLIC_KEY_SIZE];
    size_t cloud_ecdh_pubkey_len;
    uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
    size_t shared_secret_len;
    uint8_t cloud_shared_secret[ECDH_SHARED_SECRET_SIZE];
    size_t cloud_shared_secret_len;

    /* Session encryption */
    uint8_t gcm_nonce[GCM_NONCE_SIZE];
    const unsigned char plaintext[] = "SENSOR_DATA:TEMP=25.5";
    const unsigned char kdf_info[] = "optiga-session-key";
    uint8_t ciphertext[AES_BUFF_SIZE];
    uint8_t decrypted[AES_BUFF_SIZE];
    size_t ciphertext_len = 0;
    size_t decrypted_len = 0;

    /* Key attributes */
    psa_key_attributes_t device_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t ecdh_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t secret_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t session_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t kdf_op = PSA_KEY_DERIVATION_OPERATION_INIT;

    /* Working buffer */
    unsigned char out_buf[256];
    int buf_size;

    /* Initialize the device and board peripherals */
    result = cybsp_init();
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();

    /* Initialize TF-M interface */
    rslt = tfm_ns_interface_init();
    if(rslt != OS_WRAPPER_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Clear screen and print banner */
    buf_size = sprintf((char*)out_buf, "\x1b[2J\x1b[;H"
                "=======================================================\r\n"
                "  OPTIGA Trust M - Secure Communication Channel\r\n"
                "  PSoC Edge E84 | TF-M Secure Platform\r\n"
                "=======================================================\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Initialize PSA Crypto subsystem */
    psa_crypto_init();

    /* ========== Phase 1: Handshake - Device Authentication ========== */
    buf_size = sprintf((char*)out_buf,
                "========== Phase 1: Secure Handshake ==========\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "Simulating device authentication and ECDH key exchange...\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Generate device ECDSA key (simulates OPTIGA device key) */
    psa_set_key_usage_flags(&device_key_attributes,
              PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
              PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&device_key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&device_key_attributes,
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&device_key_attributes, EC_KEY_BITS);
    psa_set_key_lifetime(&device_key_attributes, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_generate_key(&device_key_attributes, &device_key_id);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Device key generation\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    /* Export public key */
    status = psa_export_public_key(device_key_id, device_public_key,
                                   sizeof(device_public_key), &device_pubkey_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Public key export\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    /* Generate challenge nonce */
    status = psa_generate_random(device_nonce, sizeof(device_nonce));
    if(status != PSA_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Sign nonce to prove device identity */
    status = psa_sign_message(device_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                              device_nonce, sizeof(device_nonce),
                              device_signature, sizeof(device_signature), &signature_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Signature generation\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    /* Display handshake messages */
    print_hex("[HS] dev_pub: ", device_public_key, device_pubkey_len, out_buf);
    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    print_hex("[HS] nonce: ", device_nonce, sizeof(device_nonce), out_buf);
    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    print_hex("[HS] sig: ", device_signature, signature_len, out_buf);
    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Verify signature (simulates server verification) */
    status = psa_verify_message(device_key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
               device_nonce, sizeof(device_nonce), device_signature, signature_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Signature verification\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "    [OK] Device authenticated\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "Performing ECDH key exchange...\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Generate device ECDH keypair */
    psa_set_key_usage_flags(&ecdh_key_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&ecdh_key_attributes, PSA_ALG_ECDH);
    psa_set_key_type(&ecdh_key_attributes,
            PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&ecdh_key_attributes, EC_KEY_BITS);
    psa_set_key_lifetime(&ecdh_key_attributes, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_generate_key(&ecdh_key_attributes, &device_ecdh_key_id);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Device ECDH key generation\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_export_public_key(device_ecdh_key_id, device_ecdh_pubkey,
                                   sizeof(device_ecdh_pubkey), &device_ecdh_pubkey_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Device ECDH public key export\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    /* Generate cloud ECDH keypair (simulated) */
    status = psa_generate_key(&ecdh_key_attributes, &cloud_ecdh_key_id);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Cloud ECDH key generation\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_export_public_key(cloud_ecdh_key_id, cloud_ecdh_pubkey,
                                   sizeof(cloud_ecdh_pubkey), &cloud_ecdh_pubkey_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Cloud ECDH public key export\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    print_hex("[HS] ecdh_dev_pub: ", device_ecdh_pubkey, device_ecdh_pubkey_len, out_buf);
    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    print_hex("[HS] ecdh_cloud_pub: ", cloud_ecdh_pubkey, cloud_ecdh_pubkey_len, out_buf);
    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    status = psa_raw_key_agreement(PSA_ALG_ECDH, device_ecdh_key_id,
                                   cloud_ecdh_pubkey, cloud_ecdh_pubkey_len,
                                   shared_secret, sizeof(shared_secret), &shared_secret_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] ECDH key agreement (device)\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_raw_key_agreement(PSA_ALG_ECDH, cloud_ecdh_key_id,
                                   device_ecdh_pubkey, device_ecdh_pubkey_len,
                                   cloud_shared_secret, sizeof(cloud_shared_secret),
                                   &cloud_shared_secret_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] ECDH key agreement (cloud)\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    if((shared_secret_len != cloud_shared_secret_len) ||
       (memcmp(shared_secret, cloud_shared_secret, shared_secret_len) != 0))
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] ECDH shared secret mismatch\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "    [OK] ECDH shared secret established\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Import shared secret as a key for HKDF input */
    psa_set_key_usage_flags(&secret_key_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&secret_key_attributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_type(&secret_key_attributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&secret_key_attributes, shared_secret_len * 8u);
    psa_set_key_lifetime(&secret_key_attributes, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_import_key(&secret_key_attributes,
                            shared_secret, shared_secret_len,
                            &shared_secret_key_id);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Shared secret import\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "    [OK] Handshake complete\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* ========== Phase 2: Session Key Derivation ========== */
    buf_size = sprintf((char*)out_buf,
                "========== Phase 2: Session Setup ==========\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "Deriving AES-GCM session key with HKDF...\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Derive session encryption key from shared secret using HKDF */
    psa_set_key_usage_flags(&session_key_attributes,
                               PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&session_key_attributes, PSA_ALG_GCM);
    psa_set_key_type(&session_key_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&session_key_attributes, AES_KEY_SIZE);
    psa_set_key_lifetime(&session_key_attributes, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_key_derivation_setup(&kdf_op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] HKDF setup\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            device_nonce, sizeof(device_nonce));
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] HKDF input salt\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_key_derivation_input_key(&kdf_op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          shared_secret_key_id);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] HKDF input secret\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            kdf_info, sizeof(kdf_info) - 1);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] HKDF input info\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_key_derivation_set_capacity(&kdf_op, AES_KEY_SIZE / 8u);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] HKDF set capacity\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_key_derivation_output_key(&session_key_attributes, &kdf_op, &session_key_id);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Session key derivation\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    status = psa_key_derivation_abort(&kdf_op);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] HKDF cleanup\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "    [OK] Session key established\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "    - Algorithm: AES-128-GCM (AEAD)\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "    - Authentication tag: 16 bytes\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* ========== Phase 3: Encrypted Data Transfer ========== */
    buf_size = sprintf((char*)out_buf,
                "========== Phase 3: Encrypted Data Transfer ==========\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Generate random nonce for GCM */
    status = psa_generate_random(gcm_nonce, sizeof(gcm_nonce));
    if(status != PSA_SUCCESS)
    {
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "[DATA] plaintext: %s\r\n", plaintext);
    ifx_platform_log_msg(out_buf, buf_size);

    /* Encrypt data with AES-GCM (AEAD) */
    status = psa_aead_encrypt(session_key_id,
                              PSA_ALG_GCM,
                              gcm_nonce, sizeof(gcm_nonce),
                              NULL, 0,  /* No additional data */
                              plaintext, sizeof(plaintext),
                              ciphertext, sizeof(ciphertext), &ciphertext_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Encryption failed\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    print_hex("[DATA] nonce: ", gcm_nonce, sizeof(gcm_nonce), out_buf);
    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    print_hex("[DATA] ciphertext+tag: ", ciphertext, ciphertext_len, out_buf);
    buf_size = sprintf((char*)out_buf, "\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "    [OK] Data encrypted (%d bytes)\r\n\r\n", ciphertext_len);
    ifx_platform_log_msg(out_buf, buf_size);

    /* Decrypt data (simulates receiver) */
    buf_size = sprintf((char*)out_buf, "Decrypting received data...\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    status = psa_aead_decrypt(session_key_id,
                              PSA_ALG_GCM,
                              gcm_nonce, sizeof(gcm_nonce),
                              NULL, 0,
                              ciphertext, ciphertext_len,
                              decrypted, sizeof(decrypted), &decrypted_len);
    if(status != PSA_SUCCESS)
    {
        buf_size = sprintf((char*)out_buf, "    [FAIL] Decryption failed (auth tag mismatch?)\r\n");
        ifx_platform_log_msg(out_buf, buf_size);
        CY_ASSERT(0);
    }

    buf_size = sprintf((char*)out_buf, "[DATA] decrypted: %s\r\n", decrypted);
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "    [OK] Data integrity verified\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* ========== Summary ========== */
    buf_size = sprintf((char*)out_buf, "=======================================================\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "  Secure channel demo completed successfully!\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "  - Device authenticated with ECDSA signature\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "  - Session key established\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "  - Data encrypted and verified with AES-GCM\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    buf_size = sprintf((char*)out_buf, "=======================================================\r\n\r\n");
    ifx_platform_log_msg(out_buf, buf_size);

    /* Cleanup */
    psa_destroy_key(device_key_id);
    psa_destroy_key(device_ecdh_key_id);
    psa_destroy_key(cloud_ecdh_key_id);
    psa_destroy_key(shared_secret_key_id);
    psa_destroy_key(session_key_id);

    /* Enable CM55 */
    Cy_SysEnableCM55(MXCM55, CM55_APP_BOOT_ADDR, CM55_BOOT_WAIT_TIME_USEC);

    for (;;)
    {
        /* Receive and forward IPC requests from M55 to TF-M */
        result = mtb_srf_ipc_receive_request(&cybsp_mtb_srf_relay_context, MTB_IPC_NEVER_TIMEOUT);
        if(result != CY_RSLT_SUCCESS)
        {
            CY_ASSERT(0);
        }
        result =  mtb_srf_ipc_process_pending_request(&cybsp_mtb_srf_relay_context);
        if(result != CY_RSLT_SUCCESS)
        {
            CY_ASSERT(0);
        }
    }
}
/* [] END OF FILE */
