#include <stdint.h>
#include <sys/endian.h>

#include "common.h"

#define EXEFS_BLOCK_SIZE 0x200
#define EXEFS_NUM_FILES  8

typedef struct { // little endian
    char        name[8];
    uint32_t    offset; // relative to end of header
    uint32_t    size;
} ExeFSFileHeader;

typedef struct {
    ExeFSFileHeader files[EXEFS_NUM_FILES];
    char            padding[0x200 - (EXEFS_NUM_FILES * 0x30)];
    uint32_t        hashes[EXEFS_NUM_FILES][8];
} ExeFSHeader;
CHECK_STRUCT_SIZE(ExeFSHeader, EXEFS_BLOCK_SIZE);

typedef struct {
    ExeFSHeader header;
    char        data[];
} *ExeFS;

static inline uint32_t CalculateExeFSSize(ExeFSHeader* header) {
    uint32_t size = 0;

    for (int i = 0; i < EXEFS_NUM_FILES; i++) {
        ExeFSFileHeader* file = &header->files[i];
        if (!file->size)
            break;

        uint32_t offset = le32toh(file->offset);
        uint32_t fsize  = le32toh(file->size);

        if (!__builtin_is_aligned(offset, EXEFS_BLOCK_SIZE))
            return 0;

        if (offset < size)
            return 0;

        size += align_up(fsize, EXEFS_BLOCK_SIZE);
    }

    return size;
}
