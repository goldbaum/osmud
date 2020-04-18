#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"


size_t strlcpy(char *dst, const char *src, size_t size)
{
    size_t    srclen;         /* Length of source string */

    /* Figure out how much room is needed */
    size--;
    srclen = strlen(src);

   /* Copy the appropriate amount */
    if (srclen > size)
      srclen = size;

    memcpy(dst, src, srclen);
    dst[srclen] = '\0';

    return (srclen);
}


char *osm_strdup(const char *s)
{
    size_t size = strlen(s) + 1;
    char *p = malloc(size);
    if (p != NULL) {
        memcpy(p, s, size);
    }
    return p;
}


char *osm_strndup(const char *s, size_t n)
{
    char *p = memchr(s, '\0', n);
    if (p != NULL)
        n = p - s;
    p = malloc(n + 1);
    if (p != NULL) {
        memcpy(p, s, n);
        p[n] = '\0';
    }
    return p;
}


int osm_read_line(char *buffer, int maxLineLength, int fd)
{
    int bytes_read;
    int k = 0;
    int fDone = 0;
    do {
        char t = 0;
        bytes_read = read(fd, &t, 1);
        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_POL_VIOLATION, "actual bytes read: %d", bytes_read);
        logOmsGeneralMessage(OMS_DEBUG, OMS_SUBSYS_POL_VIOLATION, "t: %d", t);
        if (t == '\n') {
            buffer[k]='\0';
            fDone = 1;
        }
        else if (k < maxLineLength) {
            buffer[k++] = t;
        } else {
                // printf("Line too long...");
                fDone = 1;
        }
    }
    while ((bytes_read != 0) && (!fDone));

    return k;
}
