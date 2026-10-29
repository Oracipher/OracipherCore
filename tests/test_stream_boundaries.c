// Boundary regressions for SecretStream chunk framing (Issue #39).
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "hsc_kernel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define TEST_PATH_MAX 1024
static int temp_file(char path[TEST_PATH_MAX]) {
#ifdef _WIN32
    char directory[MAX_PATH];
    DWORD len = GetTempPathA(MAX_PATH, directory);
    if (len == 0 || len >= MAX_PATH) return 0;
    char temp[MAX_PATH];
    if (GetTempFileNameA(directory, "osc", 0, temp) == 0) return 0;
    if (strlen(temp) >= TEST_PATH_MAX) {
        DeleteFileA(temp);
        return 0;
    }
    strcpy(path, temp);
    return 1;
#else
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || dir[0] == '\0') dir = "/tmp";
    const char suffix[] = "/oracipher-stream-XXXXXX";
    if (strlen(dir) + sizeof(suffix) > TEST_PATH_MAX) return 0;
    strcpy(path, dir);
    strcat(path, suffix);
    int fd = mkstemp(path);
    return fd >= 0 && close(fd) == 0;
#endif
}

static int fill_file(const char *path, size_t length) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    unsigned char block[257];
    for (size_t i = 0; i < sizeof(block); i++) block[i] = (unsigned char)(i * 37U + 11U);
    int ok = 1;
    while (length != 0) {
        size_t n = length < sizeof(block) ? length : sizeof(block);
        if (fwrite(block, 1, n, f) != n) { ok = 0; break; }
        length -= n;
    }
    if (fclose(f) != 0) ok = 0;
    return ok;
}

static int equal_files(const char *a, const char *b) {
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    if (!fa || !fb) {
        if (fa) fclose(fa);
        if (fb) fclose(fb);
        return 0;
    }
    unsigned char aa[311], bb[311];
    int success = 1;
    for (;;) {
        size_t n = fread(aa, 1, sizeof(aa), fa);
        size_t m = fread(bb, 1, sizeof(bb), fb);
        if (n != m || memcmp(aa, bb, n) != 0) { success = 0; break; }
        if (n < sizeof(aa)) {
            if (ferror(fa) || ferror(fb)) success = 0;
            break;
        }
    }
    if (fclose(fa) != 0) success = 0;
    if (fclose(fb) != 0) success = 0;
    return success;
}

static int roundtrip(size_t length, const unsigned char *recipient_pk,
                     const unsigned char *sender_pk,
                     const hsc_master_key_pair *sender,
                     const hsc_master_key_pair *recipient) {
    char input[TEST_PATH_MAX] = {0};
    char encrypted[TEST_PATH_MAX] = {0};
    char output[TEST_PATH_MAX] = {0};
    int pass = 0;
    if (!temp_file(input) || !temp_file(encrypted) || !temp_file(output)) goto cleanup;
    // The output paths must not exist because the library uses exclusive creation.
    if (remove(encrypted) != 0 || remove(output) != 0) goto cleanup;
    if (!fill_file(input, length)) goto cleanup;
    if (hsc_hybrid_encrypt_stream_raw(encrypted, input, recipient_pk, sender) != HSC_OK)
        goto cleanup;
    if (hsc_hybrid_decrypt_stream_raw(output, encrypted, recipient, sender_pk) != HSC_OK)
        goto cleanup;
    pass = equal_files(input, output);
cleanup:
    if (input[0]) remove(input);
    if (encrypted[0]) remove(encrypted);
    if (output[0]) remove(output);
    if (!pass) fprintf(stderr, "SecretStream roundtrip failed at %zu bytes\n", length);
    return pass;
}

int main(void) {
    const size_t lengths[] = {0U, 1U, 4095U, 4096U, 4097U, 8192U, 8193U};
    int initialized = 0;
    int ok = 0;
    hsc_master_key_pair *sender = NULL, *recipient = NULL;
    if (hsc_init(NULL, NULL) != HSC_OK) goto cleanup;
    initialized = 1;
    sender = hsc_generate_master_key_pair();
    recipient = hsc_generate_master_key_pair();
    if (sender == NULL || recipient == NULL) goto cleanup;
    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_get_master_public_key(sender, sender_pk, sizeof(sender_pk)) != HSC_OK)
        goto cleanup;
    if (hsc_get_master_public_key(recipient, recipient_pk, sizeof(recipient_pk)) != HSC_OK)
        goto cleanup;
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        if (!roundtrip(lengths[i], recipient_pk, sender_pk, sender, recipient))
            goto cleanup;
    }
    ok = 1;
cleanup:
    if (sender) hsc_free_master_key_pair(&sender);
    if (recipient) hsc_free_master_key_pair(&recipient);
    if (initialized) hsc_cleanup();
    if (!ok) fprintf(stderr, "SecretStream framing regression failed\n");
    return ok ? 0 : 1;
}
