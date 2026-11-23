/*
 * Planted hard case (study-made, not part of the original project).
 * Forces the vendored cJSON code and the statically linked zlib into the server binary
 * without editing any original source file: a constructor runs before main().
 *
 * zlib is exercised the way a real application would use it (compress + uncompress), so the
 * linker pulls in deflate.o and inflate.o together with their version banners
 * ("deflate 1.3.1 Copyright ...", "inflate 1.3.1 Copyright ..."). Calling only zlibVersion()
 * would link a tiny fraction of the library and under-represent a real static zlib user.
 */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "zlib.h"

__attribute__((constructor)) static void p16_vendor_hook(void) {
    static const char msg[] = "p16 planted hook";
    unsigned char packed[128], unpacked[64];
    uLongf packed_len = sizeof packed, unpacked_len = sizeof unpacked;

    int ok = compress2(packed, &packed_len, (const Bytef *)msg, sizeof msg, Z_BEST_SPEED) == Z_OK
          && uncompress(unpacked, &unpacked_len, packed, packed_len) == Z_OK
          && unpacked_len == sizeof msg && memcmp(unpacked, msg, sizeof msg) == 0;

    cJSON *info = cJSON_CreateObject();
    cJSON_AddStringToObject(info, "cjson", cJSON_Version());
    cJSON_AddStringToObject(info, "zlib", zlibVersion());
    cJSON_AddBoolToObject(info, "zlib_roundtrip_ok", ok);
    char *text = cJSON_PrintUnformatted(info);
    fprintf(stderr, "[p16] %s\n", text ? text : "{}");
    cJSON_free(text);
    cJSON_Delete(info);
}
