#pragma once

#ifndef _VIKTAR_H
# define _VIKTAR_H

#ifndef FALSE
# define FALSE 0
#endif // FALSE
#ifndef TRUE
# define TRUE 1
#endif // TRUE

# define OPTIONS "xctTf:Vhv"

# define VIKTAR_TAG "@<viktar>\n"

# define VIKTAR_MAX_FILE_NAME_LEN 25

typedef struct viktar_header_s {
    char      viktar_name[VIKTAR_MAX_FILE_NAME_LEN]; /* Member file name, usually NULL terminated. */

    off_t     st_size;        /* Total size, in bytes */
    mode_t    st_mode;        /* File type and mode */
    uid_t     st_uid;         /* User ID of owner */
    gid_t     st_gid;         /* Group ID of owner */

    struct timespec st_atim;  /* Time of last access */
    struct timespec st_mtim;  /* Time of last modification */
} viktar_header_t;

typedef struct viktar_footer_s {
    uint32_t crc32_header;
    uint32_t crc32_data; // Calculated using zlib.
} viktar_footer_t;

typedef enum {
    ACTION_NONE = 0
    , ACTION_CREATE
    , ACTION_EXTRACT
    , ACTION_TOC_SHORT
    , ACTION_TOC_LONG
    , ACTION_VALIDATE
} viktar_action_t;

#endif // _VIKTAR_H
