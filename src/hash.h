#ifndef HASH_H
#define HASH_H

/* FNV-1a over a NUL-terminated string. */
static inline unsigned int fnv1a(const char *key) {
    unsigned int h = 2166136261u;
    for (int i = 0; key[i] != '\0'; i++) {
        h ^= (unsigned char)key[i];
        h *= 16777619u;
    }
    return h;
}

#endif
