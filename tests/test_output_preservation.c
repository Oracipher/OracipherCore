// Regression tests for Issue #27: failed operations must not delete existing output.
// Uses OS-created unique temporary files to avoid overwriting unrelated user data.
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

#define PATH_BUFFER_SIZE 1024
static const unsigned char sentinel[] = "Oracipher: existing output must remain unchanged";

static int create_temp_path(char path[PATH_BUFFER_SIZE]) {
#ifdef _WIN32
    char directory[MAX_PATH];
    DWORD n = GetTempPathA(MAX_PATH, directory);
    if (n == 0 || n >= MAX_PATH) return 0;
    char temporary[MAX_PATH];
    if (GetTempFileNameA(directory, "hsc", 0, temporary) == 0) return 0;
    if (strlen(temporary) >= PATH_BUFFER_SIZE) {
        DeleteFileA(temporary);
        return 0;
    }
    strcpy(path, temporary);
    return 1;
#else
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL || tmpdir[0] == '\0') tmpdir = "/tmp";
    const char suffix[] = "/oracipher-issue27-XXXXXX";
    if (strlen(tmpdir) + sizeof(suffix) > PATH_BUFFER_SIZE) return 0;
    strcpy(path, tmpdir);
    strcat(path, suffix);
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    return close(fd) == 0;
#endif
}

static int write_sentinel(const char *path) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) return 0;
    int ok = fwrite(sentinel, 1, sizeof(sentinel), f) == sizeof(sentinel);
    if (fclose(f) != 0) ok = 0;
    return ok;
}

static int sentinel_unchanged(const char *path) {
    unsigned char actual[sizeof(sentinel) + 1];
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 0;
    size_t n = fread(actual, 1, sizeof(actual), f);
    int read_error = ferror(f);
    if (fclose(f) != 0) read_error = 1;
    return !read_error && n == sizeof(sentinel) &&
           memcmp(actual, sentinel, sizeof(sentinel)) == 0;
}

int main(void) {
    char out_path[PATH_BUFFER_SIZE] = {0};
    char input_path[PATH_BUFFER_SIZE] = {0};
    char missing_path[PATH_BUFFER_SIZE + 32] = {0};
    hsc_master_key_pair *sender = NULL;
    hsc_master_key_pair *recipient = NULL;
    int initialized = 0;
    int result = 1;

    if (!create_temp_path(out_path)) goto cleanup;
    if (!create_temp_path(input_path)) goto cleanup;
    if (!write_sentinel(out_path)) goto cleanup;

    // A unique, never-created path alongside a newly created temporary file.
    if (snprintf(missing_path, sizeof(missing_path), "%s.missing", input_path)
        >= (int)sizeof(missing_path)) goto cleanup;

    if (hsc_init(NULL, NULL) != HSC_OK) goto cleanup;
    initialized = 1;
    sender = hsc_generate_master_key_pair();
    recipient = hsc_generate_master_key_pair();
    if (sender == NULL || recipient == NULL) goto cleanup;

    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_get_master_public_key(recipient, recipient_pk, sizeof(recipient_pk)) != HSC_OK) goto cleanup;
    if (hsc_get_master_public_key(sender, sender_pk, sizeof(sender_pk)) != HSC_OK) goto cleanup;

    // Failure before output open: existing file must survive.
    if (hsc_hybrid_encrypt_stream_raw(out_path, missing_path, recipient_pk, sender)
        != HSC_ERROR_FILE_IO) goto cleanup;
    if (!sentinel_unchanged(out_path)) goto cleanup;

    // Failure because O_EXCL / CREATE_NEW refuses an existing output.
    if (hsc_hybrid_encrypt_stream_raw(out_path, input_path, recipient_pk, sender)
        != HSC_ERROR_FILE_IO) goto cleanup;
    if (!sentinel_unchanged(out_path)) goto cleanup;

    // Decryption failure before output open and on malformed ciphertext.
    if (hsc_hybrid_decrypt_stream_raw(out_path, missing_path, recipient, sender_pk)
        != HSC_ERROR_FILE_IO) goto cleanup;
    if (!sentinel_unchanged(out_path)) goto cleanup;

    if (hsc_hybrid_decrypt_stream_raw(out_path, input_path, recipient, sender_pk)
        != HSC_ERROR_INVALID_FORMAT) goto cleanup;
    if (!sentinel_unchanged(out_path)) goto cleanup;

    result = 0;
cleanup:
    if (recipient != NULL) hsc_free_master_key_pair(&recipient);
    if (sender != NULL) hsc_free_master_key_pair(&sender);
    if (initialized) hsc_cleanup();
    if (input_path[0] != '\0') remove(input_path);
    if (out_path[0] != '\0') remove(out_path);
    if (result != 0) fprintf(stderr, "Issue #27 regression: existing output preservation FAILED\n");
    return result;
}
