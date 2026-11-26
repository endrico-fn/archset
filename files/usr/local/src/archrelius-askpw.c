/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/kd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ASK_DIR      "/run/systemd/ask-password"
#define DEFAULT_MAPPER_DIR   "/dev/mapper"
#define DEFAULT_CONF_PATH    "/etc/archrelius.conf"
#define FALLBACK_AGENT       "/usr/bin/systemd-tty-ask-password-agent"

#define MAX_PASS_LEN         511
#define MAX_ROWS             160
#define MAX_COLS             512
#define BANNER_LINES         9
#define BANNER_WIDTH         116
#define ACTIVE_FRAME_MS      33
#define IDLE_FRAME_MS        500
#define DEFAULT_IDLE_SEC     15U
#define MAX_UNLOCK_WAIT_MS   60000ULL
#define MIN_SCANNER_MS       420ULL
#define FAST_SCANNER_MS      120ULL
#define GRANTED_HOLD_MS      680ULL
#define FAST_GRANTED_MS      160ULL

static const char *const BANNER_RAW[BANNER_LINES] = {
    "  ▄████████    ▄████████  ▄████████    ▄█    █▄       ▄████████    ▄████████  ▄█        ▄█  ███    █▄     ▄████████",
    "  ███    ███   ███    ███ ███    ███   ███    ███     ███    ███   ███    ███ ███       ███  ███    ███   ███    ███",
    "  ███    ███   ███    ███ ███    █▀    ███    ███     ███    ███   ███    █▀  ███       ███▌ ███    ███   ███    █▀",
    "  ███    ███  ▄███▄▄▄▄██▀ ███         ▄███▄▄▄▄███▄▄  ▄███▄▄▄▄██▀  ▄███▄▄▄     ███       ███▌ ███    ███   ███",
    "▀███████████ ▀▀███▀▀▀▀▀   ███        ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ███       ███▌ ███    ███ ▀███████████",
    "  ███    ███ ▀███████████ ███    █▄    ███    ███   ▀███████████   ███    █▄  ███       ███  ███    ███          ███",
    "  ███    ███   ███    ███ ███    ███   ███    ███     ███    ███   ███    ███ ███▌    ▄ ███  ███    ███    ▄█    ███",
    "  ███    █▀    ███    ███ ████████▀    ███    █▀      ███    ███   ██████████ █████▄▄██ █▀   ████████▀   ▄████████▀",
    "               ███    ███                             ███    ███              ▀",
};

static const int16_t SIN64[64] = {
       0,   25,   50,   74,   98,  121,  142,  162,
     181,  198,  213,  226,  237,  245,  251,  255,
     256,  255,  251,  245,  237,  226,  213,  198,
     181,  162,  142,  121,   98,   74,   50,   25,
       0,  -25,  -50,  -74,  -98, -121, -142, -162,
    -181, -198, -213, -226, -237, -245, -251, -255,
    -256, -255, -251, -245, -237, -226, -213, -198,
    -181, -162, -142, -121,  -98,  -74,  -50,  -25,
};

enum color_id {
    COL_DEFAULT = 0,
    COL_DIM_GRAY,
    COL_DEEP_TEAL,
    COL_MID_TEAL,
    COL_CYAN_GREEN,
    COL_ACCENT_TEAL,
    COL_BRIGHT_MINT,
    COL_WHITE,
    COL_SOFT_WHITE,
    COL_RED,
    COL_EMERALD,
    COL_COUNT
};

enum ui_phase {
    UI_PROMPT = 0,
    UI_UNLOCKING,
    UI_GRANTED,
};

enum pw_feedback {
    PW_MASKED = 0,
    PW_BLOCKS,
    PW_PULSE,
    PW_HIDDEN,
};

struct rgb {
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

struct ui_config {
    bool show_intro;
    bool show_banner;
    enum pw_feedback pw_mode;
    uint64_t idle_after_ms;
    char compact_title[33];
    struct rgb pal[COL_COUNT];
    char sgr_pty[COL_COUNT][28];
};

struct cell {
    char utf8[5];
    uint8_t color;
};

struct banner_glyph {
    char utf8[5];
    bool is_edge;
};

struct anim_ctx {
    bool is_linux_vt;
    bool skip_intro;
    bool force_full_redraw;
    uint64_t boot_ms;
    uint64_t intro_start_ms;
    uint64_t ripple_start_ms;
    uint64_t error_start_ms;
    uint64_t last_input_ms;
};

struct tty_session {
    int fd;
    bool have_orig;
    bool is_raw;
    bool is_linux_vt;
    struct termios orig_tio;
    struct termios raw_tio;
};

struct ask_request {
    char ask_path[PATH_MAX];
    char socket_path[PATH_MAX];
    char id[256];
    char message[256];
    char prompt_title[192];
    pid_t pid;
    uint64_t not_after_usec;
};

struct secret_page {
    char pass[MAX_PASS_LEN + 1];
    char pkt[MAX_PASS_LEN + 2];
    char pad[4096 - ((MAX_PASS_LEN + 1 + MAX_PASS_LEN + 2) % 4096)];
} __attribute__((aligned(4096)));

static struct secret_page g_secret;
static struct banner_glyph g_banner[BANNER_LINES][BANNER_WIDTH];
static struct cell g_canvas[MAX_ROWS][MAX_COLS];
static struct cell g_prev_canvas[MAX_ROWS][MAX_COLS];
static char g_outbuf[524288];

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_winch = 0;

static inline int fast_sin(int idx) {
    return SIN64[idx & 63];
}

static void on_stop_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void on_winch_signal(int sig) {
    (void)sig;
    g_winch = 1;
}

static void copy_str(char *dst, size_t dst_sz, const char *src) {
    if (!dst || dst_sz == 0)
        return;
    size_t n = src ? strnlen(src, dst_sz - 1) : 0;
    if (n > 0)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

static void harden_process_memory(void) {
    struct rlimit rl = {.rlim_cur = 0, .rlim_max = 0};
    (void)setrlimit(RLIMIT_CORE, &rl);
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    explicit_bzero(&g_secret, sizeof(g_secret));
    (void)mlock(&g_secret, sizeof(g_secret));
#ifdef MADV_DONTDUMP
    (void)madvise(&g_secret, sizeof(g_secret), MADV_DONTDUMP);
#endif
}

static void wipe_secrets(void) {
    explicit_bzero(&g_secret, sizeof(g_secret));
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR && !g_stop)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (poll(&pfd, 1, 40) > 0 && !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
                    continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void write_str(int fd, const char *s) {
    if (s && *s)
        (void)write_all(fd, s, strlen(s));
}

static uint64_t now_monotonic_usec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static uint64_t now_ms(void) {
    return now_monotonic_usec() / 1000ULL;
}

static void rebuild_pty_sgr(struct ui_config *cfg) {
    copy_str(cfg->sgr_pty[COL_DEFAULT], sizeof(cfg->sgr_pty[0]), "\033[0m");
    for (int c = 1; c < COL_COUNT; c++) {
        bool bold = (c == COL_ACCENT_TEAL || c == COL_BRIGHT_MINT ||
                     c == COL_WHITE || c == COL_RED || c == COL_EMERALD);
        snprintf(cfg->sgr_pty[c], sizeof(cfg->sgr_pty[c]),
                 bold ? "\033[1;38;2;%u;%u;%um" : "\033[38;2;%u;%u;%um",
                 (unsigned)cfg->pal[c].r,
                 (unsigned)cfg->pal[c].g,
                 (unsigned)cfg->pal[c].b);
    }
}

static void init_default_config(struct ui_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->show_intro = true;
    cfg->show_banner = true;
    cfg->pw_mode = PW_MASKED;
    cfg->idle_after_ms = (uint64_t)DEFAULT_IDLE_SEC * 1000ULL;
    copy_str(cfg->compact_title, sizeof(cfg->compact_title), "ARCHRELIUS");

    cfg->pal[COL_DIM_GRAY]    = (struct rgb){0x46, 0x59, 0x56};
    cfg->pal[COL_DEEP_TEAL]   = (struct rgb){0x23, 0x59, 0x52};
    cfg->pal[COL_MID_TEAL]    = (struct rgb){0x3d, 0x8f, 0x83};
    cfg->pal[COL_CYAN_GREEN]  = (struct rgb){0x52, 0xa8, 0x99};
    cfg->pal[COL_ACCENT_TEAL] = (struct rgb){0x64, 0xbe, 0xaf};
    cfg->pal[COL_BRIGHT_MINT] = (struct rgb){0x8a, 0xe3, 0xd2};
    cfg->pal[COL_WHITE]       = (struct rgb){0xff, 0xff, 0xff};
    cfg->pal[COL_SOFT_WHITE]  = (struct rgb){0xd8, 0xe6, 0xe3};
    cfg->pal[COL_RED]         = (struct rgb){0xe0, 0x6c, 0x75};
    cfg->pal[COL_EMERALD]     = (struct rgb){0x56, 0xb8, 0x8d};

    rebuild_pty_sgr(cfg);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

static bool parse_hex_rgb(const char *s, struct rgb *out) {
    if (!s)
        return false;
    if (*s == '#')
        s++;
    if (strlen(s) != 6)
        return false;
    int hi0 = hex_nibble(s[0]), lo0 = hex_nibble(s[1]);
    int hi1 = hex_nibble(s[2]), lo1 = hex_nibble(s[3]);
    int hi2 = hex_nibble(s[4]), lo2 = hex_nibble(s[5]);
    if (hi0 < 0 || lo0 < 0 || hi1 < 0 || lo1 < 0 || hi2 < 0 || lo2 < 0)
        return false;
    out->r = (uint8_t)((hi0 << 4) | lo0);
    out->g = (uint8_t)((hi1 << 4) | lo1);
    out->b = (uint8_t)((hi2 << 4) | lo2);
    return true;
}

static bool parse_bool_val(const char *s, bool *out) {
    if (!s)
        return false;
    if (strcasecmp(s, "1") == 0 || strcasecmp(s, "true") == 0 ||
        strcasecmp(s, "yes") == 0 || strcasecmp(s, "on") == 0) {
        *out = true;
        return true;
    }
    if (strcasecmp(s, "0") == 0 || strcasecmp(s, "false") == 0 ||
        strcasecmp(s, "no") == 0 || strcasecmp(s, "off") == 0) {
        *out = false;
        return true;
    }
    return false;
}

static bool parse_safe_ascii_title(const char *s, char *out, size_t out_sz) {
    if (!s || !*s)
        return false;
    size_t len = strlen(s);
    if (len == 0 || len >= out_sz)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char uc = (unsigned char)s[i];
        if (uc < 0x20 || uc > 0x7e)
            return false;
    }
    copy_str(out, out_sz, s);
    return true;
}

static char *trim_ws(char *s) {
    while (*s == ' ' || *s == '\t')
        s++;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
                       s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
    return s;
}

static void strip_quotes(char *s) {
    size_t len = strlen(s);
    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') ||
                     (s[0] == '\'' && s[len - 1] == '\''))) {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static void load_ui_config(struct ui_config *cfg, const char *conf_path, bool custom_env) {
    if (!conf_path || !*conf_path)
        return;

    int fd = open(conf_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return;

    struct stat st;
    uid_t req_uid = custom_env ? geteuid() : 0;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != req_uid ||
        (st.st_mode & 0022) != 0 || st.st_size < 0 || st.st_size > 16384) {
        close(fd);
        return;
    }

    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        close(fd);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        bool has_ctrl = false;
        for (size_t i = 0; line[i] != '\0'; i++) {
            unsigned char uc = (unsigned char)line[i];
            if ((uc < 0x20 && uc != '\t' && uc != '\r' && uc != '\n') || uc == 0x7f) {
                has_ctrl = true;
                break;
            }
        }
        if (has_ctrl)
            continue;

        char *p = trim_ws(line);
        if (*p == '\0' || *p == '#' || *p == ';')
            continue;

        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = trim_ws(p);
        char *val = trim_ws(eq + 1);
        strip_quotes(val);

        bool b = false;
        struct rgb col;

        if (strcmp(key, "intro") == 0) {
            if (parse_bool_val(val, &b))
                cfg->show_intro = b;
        } else if (strcmp(key, "banner") == 0) {
            if (parse_bool_val(val, &b))
                cfg->show_banner = b;
        } else if (strcmp(key, "compact_title") == 0) {
            (void)parse_safe_ascii_title(val, cfg->compact_title, sizeof(cfg->compact_title));
        } else if (strcmp(key, "password_feedback") == 0) {
            if (strcasecmp(val, "masked") == 0 || strcasecmp(val, "dots") == 0)
                cfg->pw_mode = PW_MASKED;
            else if (strcasecmp(val, "blocks") == 0)
                cfg->pw_mode = PW_BLOCKS;
            else if (strcasecmp(val, "pulse") == 0)
                cfg->pw_mode = PW_PULSE;
            else if (strcasecmp(val, "hidden") == 0 || strcasecmp(val, "none") == 0)
                cfg->pw_mode = PW_HIDDEN;
        } else if (strcmp(key, "idle_timeout_sec") == 0) {
            char *endp = NULL;
            unsigned long sec = strtoul(val, &endp, 10);
            if (endp && *endp == '\0' && (sec == 0 || (sec >= 5 && sec <= 600)))
                cfg->idle_after_ms = (uint64_t)sec * 1000ULL;
        } else if (strcmp(key, "accent_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_ACCENT_TEAL] = col;
        } else if (strcmp(key, "highlight_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_BRIGHT_MINT] = col;
        } else if (strcmp(key, "mid_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_MID_TEAL] = col;
        } else if (strcmp(key, "deep_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_DEEP_TEAL] = col;
        } else if (strcmp(key, "cyan_green_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_CYAN_GREEN] = col;
        } else if (strcmp(key, "dim_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_DIM_GRAY] = col;
        } else if (strcmp(key, "soft_white_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_SOFT_WHITE] = col;
        } else if (strcmp(key, "error_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_RED] = col;
        } else if (strcmp(key, "success_color") == 0 && parse_hex_rgb(val, &col)) {
            cfg->pal[COL_EMERALD] = col;
        }
    }
    fclose(fp);
    rebuild_pty_sgr(cfg);
}

static void apply_vt_palette(int tty_fd, bool is_linux_vt, const struct ui_config *cfg) {
    if (!is_linux_vt)
        return;
    static const struct {
        char hex_slot;
        enum color_id cid;
    } map[] = {
        {'2', COL_CYAN_GREEN},
        {'4', COL_DEEP_TEAL},
        {'6', COL_ACCENT_TEAL},
        {'7', COL_SOFT_WHITE},
        {'8', COL_DIM_GRAY},
        {'9', COL_RED},
        {'A', COL_EMERALD},
        {'C', COL_MID_TEAL},
        {'E', COL_BRIGHT_MINT},
        {'F', COL_WHITE},
    };
    char seq[160];
    size_t pos = 0;
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        const struct rgb *c = &cfg->pal[map[i].cid];
        pos += (size_t)snprintf(seq + pos, sizeof(seq) - pos,
                                "\033]P%c%02x%02x%02x",
                                map[i].hex_slot,
                                (unsigned)c->r, (unsigned)c->g, (unsigned)c->b);
    }
    (void)write_all(tty_fd, seq, pos);
}

static const char *color_seq(enum color_id c, bool is_linux_vt, const struct ui_config *cfg) {
    if (c <= COL_DEFAULT || c >= COL_COUNT)
        return "\033[0m";
    if (is_linux_vt) {
        switch (c) {
            case COL_DIM_GRAY:    return "\033[0;90m";
            case COL_DEEP_TEAL:   return "\033[0;34m";
            case COL_MID_TEAL:    return "\033[1;34m";
            case COL_CYAN_GREEN:  return "\033[0;32m";
            case COL_ACCENT_TEAL: return "\033[0;36m";
            case COL_BRIGHT_MINT: return "\033[1;36m";
            case COL_WHITE:       return "\033[1;37m";
            case COL_SOFT_WHITE:  return "\033[0;37m";
            case COL_RED:         return "\033[1;31m";
            case COL_EMERALD:     return "\033[1;32m";
            default:              return "\033[0m";
        }
    }
    return cfg->sgr_pty[c];
}

static size_t utf8_seq_len(unsigned char lead) {
    if (lead < 0x80)
        return 1;
    if ((lead & 0xE0) == 0xC0)
        return 2;
    if ((lead & 0xF0) == 0xE0)
        return 3;
    if ((lead & 0xF8) == 0xF0)
        return 4;
    return 1;
}

static int utf8_display_cols(const char *s) {
    if (!s)
        return 0;
    int count = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        size_t clen = utf8_seq_len(*p);
        for (size_t k = 1; k < clen; k++) {
            if (p[k] == '\0') {
                clen = k;
                break;
            }
        }
        p += clen;
        count++;
    }
    return count;
}

static size_t count_utf8_chars(const char *buf, size_t byte_len) {
    size_t count = 0;
    size_t i = 0;
    while (i < byte_len && buf[i] != '\0') {
        size_t step = utf8_seq_len((unsigned char)buf[i]);
        if (i + step > byte_len)
            step = 1;
        i += step;
        count++;
    }
    return count;
}

static int decode_utf8_cells(const char *s, char out[][5], int max_cells) {
    if (!s || max_cells <= 0)
        return 0;
    int count = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p && count < max_cells) {
        size_t clen = utf8_seq_len(*p);
        size_t k = 0;
        for (; k < clen && p[k] != '\0'; k++)
            out[count][k] = (char)p[k];
        out[count][k] = '\0';
        if (k == 1 && (unsigned char)out[count][0] < 0x20) {
            p++;
            continue;
        }
        p += k;
        count++;
    }
    return count;
}

static void decode_banner_once(void) {
    for (int r = 0; r < BANNER_LINES; r++) {
        for (int c = 0; c < BANNER_WIDTH; c++) {
            copy_str(g_banner[r][c].utf8, sizeof(g_banner[r][c].utf8), " ");
            g_banner[r][c].is_edge = false;
        }
        const unsigned char *p = (const unsigned char *)BANNER_RAW[r];
        int col = 0;
        while (*p && col < BANNER_WIDTH) {
            size_t clen = utf8_seq_len(*p);
            memcpy(g_banner[r][col].utf8, p, clen);
            g_banner[r][col].utf8[clen] = '\0';
            if (strcmp(g_banner[r][col].utf8, "▄") == 0 ||
                strcmp(g_banner[r][col].utf8, "▀") == 0 ||
                strcmp(g_banner[r][col].utf8, "▌") == 0) {
                g_banner[r][col].is_edge = true;
            }
            p += clen;
            col++;
        }
    }
}

static void init_anim_ctx(struct anim_ctx *ctx, int tty_fd, const struct ui_config *cfg) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->skip_intro = !cfg->show_intro;
    ctx->force_full_redraw = true;
    uint64_t t = now_ms();
    ctx->boot_ms = t;
    ctx->intro_start_ms = t;
    ctx->last_input_ms = t;

    long kd_mode = 0;
    ctx->is_linux_vt = (ioctl(tty_fd, KDGETMODE, &kd_mode) == 0);
}

static void tty_enter_raw(struct tty_session *tty, const struct ui_config *cfg) {
    if (tty->fd < 0)
        return;
    if (!tty->have_orig && tcgetattr(tty->fd, &tty->orig_tio) == 0) {
        tty->have_orig = true;
        tty->raw_tio = tty->orig_tio;
        tty->raw_tio.c_lflag &= (tcflag_t) ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON | ISIG | IEXTEN);
        tty->raw_tio.c_iflag &= (tcflag_t) ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
        tty->raw_tio.c_cc[VMIN] = 1;
        tty->raw_tio.c_cc[VTIME] = 0;
    }
    if (tty->have_orig) {
        (void)tcsetattr(tty->fd, TCSANOW, &tty->raw_tio);
        (void)tcflush(tty->fd, TCIFLUSH);
    }
    apply_vt_palette(tty->fd, tty->is_linux_vt, cfg);
    write_str(tty->fd, "\033[?7l\033[?25l\033[0m\033[2J\033[H");
    tty->is_raw = true;
}

static void tty_reassert_raw(struct tty_session *tty, const struct ui_config *cfg) {
    if (tty->fd < 0)
        return;
    if (tty->have_orig)
        (void)tcsetattr(tty->fd, TCSANOW, &tty->raw_tio);
    apply_vt_palette(tty->fd, tty->is_linux_vt, cfg);
    write_str(tty->fd, "\033[?7l\033[?25l");
}

static void tty_restore(struct tty_session *tty) {
    if (tty->fd < 0 || !tty->is_raw)
        return;
    if (tty->have_orig) {
        (void)tcflush(tty->fd, TCIFLUSH);
        (void)tcsetattr(tty->fd, TCSANOW, &tty->orig_tio);
    }
    if (tty->is_linux_vt)
        write_str(tty->fd, "\033]R\033[0m\033[?7h\033[?25h\033[2J\033[H");
    else
        write_str(tty->fd, "\033[0m\033[?7h\033[?25h\033[2J\033[H");
    tty->is_raw = false;
}

static bool is_capslock_on(int tty_fd, bool is_linux_vt) {
    if (!is_linux_vt || tty_fd < 0)
        return false;
    char leds = 0;
    if (ioctl(tty_fd, KDGKBLED, &leds) < 0)
        return false;
    return (leds & K_CAPSLOCK) != 0;
}

static void sd_notify_ready(void) {
    const char *sock = getenv("NOTIFY_SOCKET");
    if (!sock || (sock[0] != '/' && sock[0] != '@'))
        return;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;

    size_t slen = strlen(sock);
    if (slen >= sizeof(sa.sun_path))
        return;

    socklen_t addrlen;
    if (sock[0] == '@') {
        sa.sun_path[0] = '\0';
        memcpy(sa.sun_path + 1, sock + 1, slen - 1);
        addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + slen);
    } else {
        memcpy(sa.sun_path, sock, slen);
        addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + slen + 1);
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return;
    static const char payload[] = "READY=1\n";
    (void)sendto(fd, payload, sizeof(payload) - 1, MSG_NOSIGNAL,
                 (const struct sockaddr *)&sa, addrlen);
    close(fd);
}

static bool read_sysfs_token(const char *path, char *out, size_t out_sz) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return false;
    buf[n] = '\0';

    char *last = NULL;
    char *save = NULL;
    for (char *tok = strtok_r(buf, " \t\r\n", &save); tok; tok = strtok_r(NULL, " \t\r\n", &save))
        last = tok;
    if (!last || !*last)
        return false;
    copy_str(out, out_sz, last);
    return true;
}

static int open_console_tty(const char *explicit_tty) {
    const int flags = O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK;
    if (explicit_tty && *explicit_tty)
        return open(explicit_tty, flags);

    char active[64] = {0};
    char vt_active[64] = {0};
    char devpath[96] = {0};

    if (read_sysfs_token("/sys/class/tty/console/active", active, sizeof(active))) {
        if (strcmp(active, "tty0") == 0 &&
            read_sysfs_token("/sys/class/tty/tty0/active", vt_active, sizeof(vt_active))) {
            snprintf(devpath, sizeof(devpath), "/dev/%s", vt_active);
        } else {
            snprintf(devpath, sizeof(devpath), "/dev/%s", active);
        }
        int fd = open(devpath, flags);
        if (fd >= 0)
            return fd;
    }

    static const char *const candidates[] = {"/dev/tty1", "/dev/tty0", "/dev/console"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        int fd = open(candidates[i], flags);
        if (fd >= 0)
            return fd;
    }
    return -1;
}

static void sanitize_printable_ascii(const char *in, char *out, size_t out_sz) {
    if (!out || out_sz == 0)
        return;
    size_t j = 0;
    for (size_t i = 0; in && in[i] != '\0' && j + 1 < out_sz; i++) {
        unsigned char uc = (unsigned char)in[i];
        if (uc >= 0x20 && uc <= 0x7e)
            out[j++] = (char)uc;
    }
    while (j > 0 && out[j - 1] == ' ')
        j--;
    out[j] = '\0';
}

static void derive_prompt_title(const struct ask_request *req, char *out, size_t out_sz) {
    if (strncmp(req->id, "cryptsetup:", 11) == 0) {
        const char *src = req->id + 11;
        char resolved[PATH_MAX];
        char clean_dev[128];
        if (realpath(src, resolved) != NULL)
            sanitize_printable_ascii(resolved, clean_dev, sizeof(clean_dev));
        else
            sanitize_printable_ascii(src, clean_dev, sizeof(clean_dev));

        if (clean_dev[0] != '\0') {
            snprintf(out, out_sz, " Enter passphrase for %.127s: ", clean_dev);
            return;
        }
    }

    char clean_msg[140];
    sanitize_printable_ascii(req->message, clean_msg, sizeof(clean_msg));
    if (clean_msg[0] != '\0') {
        size_t len = strlen(clean_msg);
        if (clean_msg[len - 1] == ':')
            snprintf(out, out_sz, " %.140s ", clean_msg);
        else
            snprintf(out, out_sz, " %.139s: ", clean_msg);
        return;
    }

    copy_str(out, out_sz, " Enter passphrase: ");
}

static bool has_dotdot_segment(const char *p) {
    if (!p)
        return true;
    const char *s = p;
    while (*s) {
        if (s[0] == '.' && s[1] == '.' && (s[2] == '/' || s[2] == '\0'))
            return true;
        while (*s && *s != '/')
            s++;
        while (*s == '/')
            s++;
    }
    return false;
}

static bool is_trusted_socket(const char *socket_path, const char *ask_dir, bool custom_env) {
    if (!socket_path || socket_path[0] != '/' || has_dotdot_segment(socket_path))
        return false;

    if (!custom_env) {
        size_t dlen = strlen(ask_dir);
        if (strncmp(socket_path, ask_dir, dlen) != 0 || socket_path[dlen] != '/')
            return false;
    }

    struct stat st;
    if (lstat(socket_path, &st) < 0)
        return false;
    uid_t req_uid = custom_env ? geteuid() : 0;
    return S_ISSOCK(st.st_mode) && (st.st_uid == req_uid);
}

static bool is_request_expired(const struct ask_request *req) {
    if (req->not_after_usec > 0) {
        uint64_t now = now_monotonic_usec();
        if (now > 0 && now > req->not_after_usec)
            return true;
    }
    if (req->pid > 0 && kill(req->pid, 0) < 0 && errno == ESRCH)
        return true;
    return false;
}

static bool parse_ask_file(
    const char *ask_path,
    const char *ask_dir,
    bool custom_env,
    struct ask_request *req
) {
    int fd = open(ask_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return false;

    struct stat st;
    uid_t req_uid = custom_env ? geteuid() : 0;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != req_uid ||
        st.st_size < 0 || st.st_size > 65536) {
        close(fd);
        return false;
    }

    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        close(fd);
        return false;
    }

    memset(req, 0, sizeof(*req));
    copy_str(req->ask_path, sizeof(req->ask_path), ask_path);

    bool in_ask = false;
    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p = trim_ws(line);
        if (*p == '\0' || *p == '#' || *p == ';')
            continue;
        if (*p == '[') {
            in_ask = (strcmp(p, "[Ask]") == 0);
            continue;
        }
        if (!in_ask)
            continue;

        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        const char *key = trim_ws(p);
        const char *val = trim_ws(eq + 1);

        if (strcmp(key, "Socket") == 0) {
            copy_str(req->socket_path, sizeof(req->socket_path), val);
        } else if (strcmp(key, "Id") == 0) {
            copy_str(req->id, sizeof(req->id), val);
        } else if (strcmp(key, "Message") == 0) {
            copy_str(req->message, sizeof(req->message), val);
        } else if (strcmp(key, "PID") == 0) {
            req->pid = (pid_t)strtol(val, NULL, 10);
        } else if (strcmp(key, "NotAfter") == 0) {
            req->not_after_usec = (uint64_t)strtoull(val, NULL, 10);
        }
    }
    fclose(fp);

    if (!is_trusted_socket(req->socket_path, ask_dir, custom_env))
        return false;
    if (is_request_expired(req))
        return false;

    derive_prompt_title(req, req->prompt_title, sizeof(req->prompt_title));
    return true;
}

static bool find_pending_request(
    const char *ask_dir,
    bool custom_env,
    const char *exclude_path,
    struct ask_request *req
) {
    DIR *dir = opendir(ask_dir);
    if (!dir)
        return false;

    bool found = false;
    struct timespec best_mtim = {0, 0};
    char best_name[256] = {0};
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, "ask.", 4) != 0)
            continue;
        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s/%s", ask_dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(full))
            continue;
        if (exclude_path && exclude_path[0] != '\0' && strcmp(full, exclude_path) == 0)
            continue;
        struct stat st;
        if (lstat(full, &st) < 0 || !S_ISREG(st.st_mode))
            continue;
        struct ask_request cand;
        if (!parse_ask_file(full, ask_dir, custom_env, &cand))
            continue;
        bool take = false;
        if (!found) {
            take = true;
        } else if (st.st_mtim.tv_sec < best_mtim.tv_sec) {
            take = true;
        } else if (st.st_mtim.tv_sec == best_mtim.tv_sec &&
                   st.st_mtim.tv_nsec < best_mtim.tv_nsec) {
            take = true;
        } else if (st.st_mtim.tv_sec == best_mtim.tv_sec &&
                   st.st_mtim.tv_nsec == best_mtim.tv_nsec &&
                   strcmp(de->d_name, best_name) < 0) {
            take = true;
        }
        if (take) {
            *req = cand;
            best_mtim = st.st_mtim;
            copy_str(best_name, sizeof(best_name), de->d_name);
            found = true;
        }
    }
    closedir(dir);
    return found;
}

static int count_mapper_targets(const char *mapper_dir) {
    DIR *dir = opendir(mapper_dir ? mapper_dir : DEFAULT_MAPPER_DIR);
    if (!dir)
        return 0;
    int count = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.' || strcmp(de->d_name, "control") == 0)
            continue;
        count++;
    }
    closedir(dir);
    return count;
}

static void get_term_size(int tty_fd, int *rows, int *cols) {
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    if (ioctl(tty_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col >= 20 && ws.ws_row >= 8) {
        *rows = (ws.ws_row < MAX_ROWS) ? (int)ws.ws_row : MAX_ROWS;
        *cols = (ws.ws_col < MAX_COLS) ? (int)ws.ws_col : MAX_COLS;
    } else {
        *rows = 48;
        *cols = 170;
    }
}

static void clear_canvas(int rows, int cols) {
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            g_canvas[r][c].utf8[0] = ' ';
            g_canvas[r][c].utf8[1] = '\0';
            g_canvas[r][c].color = COL_DEFAULT;
        }
    }
}

static void put_cell(int r, int c, int rows, int cols, const char *glyph, enum color_id col_id) {
    if (r < 0 || r >= rows || c < 0 || c >= cols)
        return;
    if (r == rows - 1 && c == cols - 1)
        return;
    copy_str(g_canvas[r][c].utf8, sizeof(g_canvas[r][c].utf8), glyph);
    g_canvas[r][c].color = (uint8_t)col_id;
}

static void put_utf8_str(int r, int c, int rows, int cols, const char *s, enum color_id col_id) {
    if (!s)
        return;
    const unsigned char *p = (const unsigned char *)s;
    int col_off = 0;
    while (*p) {
        size_t clen = utf8_seq_len(*p);
        char glyph[5] = {0};
        size_t k = 0;
        for (; k < clen && p[k] != '\0'; k++)
            glyph[k] = (char)p[k];
        glyph[k] = '\0';
        if (k == 1 && (unsigned char)glyph[0] < 0x20) {
            p++;
            continue;
        }
        put_cell(r, c + col_off, rows, cols, glyph, col_id);
        p += k;
        col_off++;
    }
}

static enum color_id comet_border_color(
    int idx,
    int perim,
    int head1,
    int head2,
    enum color_id base
) {
    if (perim <= 0 || base == COL_RED || base == COL_EMERALD)
        return base;
    int d1 = (head1 - idx) % perim;
    if (d1 < 0)
        d1 += perim;
    int d2 = (head2 - idx) % perim;
    if (d2 < 0)
        d2 += perim;
    int d = (d1 < d2) ? d1 : d2;
    if (d == 0)
        return COL_WHITE;
    if (d == 1)
        return COL_BRIGHT_MINT;
    if (d <= 3)
        return COL_ACCENT_TEAL;
    if (d == 4)
        return COL_MID_TEAL;
    return base;
}

static void render_frame(
    int tty_fd,
    struct anim_ctx *ctx,
    const struct ui_config *cfg,
    const char *prompt_title,
    size_t typed_glyph_count,
    bool show_err,
    bool is_preview,
    enum ui_phase phase,
    uint64_t phase_elapsed_ms,
    int *out_rows,
    int *out_cols
) {
    static const char *const CIPHER_GLYPHS[] = {
        "0", "1", "A", "C", "E", "F", "7", "9", "░", "▒", "▓", "≡", "≈"
    };

    int rows = 48, cols = 170;
    get_term_size(tty_fd, &rows, &cols);
    if (out_rows)
        *out_rows = rows;
    if (out_cols)
        *out_cols = cols;

    uint64_t t_now = now_ms();
    uint64_t elapsed_boot = (t_now >= ctx->boot_ms) ? (t_now - ctx->boot_ms) : 0;
    int tick = (int)(elapsed_boot / (uint64_t)ACTIVE_FRAME_MS);

    clear_canvas(rows, cols);

    int raw_title_len = utf8_display_cols(prompt_title);
    int inner_w = 50;
    if (raw_title_len + 8 > inner_w)
        inner_w = raw_title_len + 8;
    if (inner_w + 2 > cols - 2)
        inner_w = cols - 4;
    if (inner_w < 22)
        inner_w = 22;
    if ((inner_w & 1) && inner_w + 3 < cols)
        inner_w++;

    int max_title = inner_w - 4;
    if (max_title > 190)
        max_title = 190;
    if (max_title < 1)
        max_title = 1;
    char title_cells[192][5];
    int title_len = decode_utf8_cells(prompt_title, title_cells, max_title);

    bool full_banner = cfg->show_banner && (cols >= BANNER_WIDTH + 4 && rows >= BANNER_LINES + 9);
    int total_h = full_banner ? (BANNER_LINES + 3 + 3 + 2) : 7;
    int start_row = (rows - total_h) * 42 / 100;
    if (start_row < 1)
        start_row = 1;
    int banner_col = (cols - BANNER_WIDTH) / 2;
    if (banner_col < 0)
        banner_col = 0;
    int box_row = full_banner ? (start_row + BANNER_LINES + 3) : (start_row + 3);

    int shake_dx = 0;
    if (phase == UI_PROMPT && ctx->error_start_ms > 0 && t_now >= ctx->error_start_ms) {
        uint64_t dt_err = t_now - ctx->error_start_ms;
        if (dt_err < 360) {
            static const int SHAKE_SEQ[12] = {-3, 3, -2, 2, -2, 1, -1, 1, 0, 0, 0, 0};
            shake_dx = SHAKE_SEQ[(dt_err * 12) / 360];
        }
    }

    uint64_t dt_intro = ctx->skip_intro
                            ? 99999ULL
                            : (t_now >= ctx->intro_start_ms ? t_now - ctx->intro_start_ms : 0);
    int reveal_col = (dt_intro < 720)
                         ? (int)((dt_intro * (BANNER_WIDTH + 18)) / 720) - 8
                         : BANNER_WIDTH + 20;

    if (full_banner) {
        int grant_front = (phase == UI_GRANTED)
                              ? (int)((phase_elapsed_ms * (uint64_t)(BANNER_WIDTH + 32)) / 520ULL) - 12
                              : -999;

        for (int r = 0; r < BANNER_LINES; r++) {
            for (int c = 0; c < BANNER_WIDTH; c++) {
                const struct banner_glyph *bg = &g_banner[r][c];
                if (bg->utf8[0] == ' ')
                    continue;

                int slant_c = c + r * 2;
                if (slant_c > reveal_col + 9)
                    continue;
                if (slant_c > reveal_col) {
                    uint32_t h = (uint32_t)(r * 131 + c * 17 + tick * 7);
                    enum color_id wc = (slant_c - reveal_col <= 2)
                                           ? COL_WHITE
                                           : (slant_c - reveal_col <= 5 ? COL_BRIGHT_MINT : COL_CYAN_GREEN);
                    put_cell(start_row + r, banner_col + c, rows, cols, CIPHER_GLYPHS[h % 13], wc);
                    continue;
                }

                enum color_id pcol = COL_ACCENT_TEAL;
                if (phase == UI_GRANTED) {
                    int gd = slant_c - grant_front;
                    if (gd < 0)
                        gd = -gd;
                    if (gd <= 2)
                        pcol = COL_WHITE;
                    else if (gd <= 9)
                        pcol = COL_BRIGHT_MINT;
                    else
                        pcol = (r == 0 && bg->is_edge) ? COL_BRIGHT_MINT : COL_EMERALD;
                } else {
                    int w = (c * 3 - r * 7 - tick * 4) % 360;
                    if (w < 0)
                        w += 360;
                    if (w < 6)
                        pcol = COL_WHITE;
                    else if (w < 22)
                        pcol = COL_BRIGHT_MINT;
                    else if (w < 36)
                        pcol = bg->is_edge ? COL_BRIGHT_MINT : COL_ACCENT_TEAL;
                    else if (w >= 168 && w < 188)
                        pcol = COL_CYAN_GREEN;
                    else if (w >= 188 && w < 210)
                        pcol = COL_MID_TEAL;
                    else if (w >= 210 && w < 228)
                        pcol = COL_CYAN_GREEN;
                    else if (r == 0 && bg->is_edge)
                        pcol = COL_BRIGHT_MINT;
                    else if (r >= 7 && !bg->is_edge)
                        pcol = COL_CYAN_GREEN;
                    else
                        pcol = COL_ACCENT_TEAL;
                }

                put_cell(start_row + r, banner_col + c, rows, cols, bg->utf8, pcol);
            }
        }
    } else {
        int tlen = utf8_display_cols(cfg->compact_title);
        enum color_id hcol = (phase == UI_GRANTED) ? COL_EMERALD : COL_BRIGHT_MINT;
        put_utf8_str(start_row, (cols - tlen) / 2, rows, cols, cfg->compact_title, hcol);
        if (start_row + 1 < box_row) {
            int rule_w = (tlen + 6 < cols - 4) ? (tlen + 6) : tlen;
            int r0 = (cols - rule_w) / 2;
            enum color_id rcol = (phase == UI_GRANTED) ? COL_EMERALD : COL_ACCENT_TEAL;
            for (int i = 0; i < rule_w; i++)
                put_cell(start_row + 1, r0 + i, rows, cols, "─", rcol);
        }
    }

    /* Quadratic ease-out box expansion on boot intro */
    int cur_inner_w = inner_w;
    if (!ctx->skip_intro && dt_intro < 400) {
        uint64_t inv = 400ULL - dt_intro;
        uint64_t eased = 160000ULL - inv * inv;
        cur_inner_w = 8 + (int)((eased * (uint64_t)(inner_w - 8)) / 160000ULL);
        if (cur_inner_w & 1)
            cur_inner_w++;
        if (cur_inner_w > inner_w)
            cur_inner_w = inner_w;
    }
    int cur_box_w = cur_inner_w + 2;
    int cur_box_col = (cols - cur_box_w) / 2 + shake_dx;

    enum color_id border_base = COL_SOFT_WHITE;
    if (phase == UI_GRANTED) {
        border_base = COL_EMERALD;
    } else if (phase == UI_PROMPT && ctx->error_start_ms > 0 &&
               t_now >= ctx->error_start_ms && (t_now - ctx->error_start_ms) < 650) {
        border_base = COL_RED;
    }

    int perim = 2 * cur_inner_w + 6;
    int head1 = tick % perim;
    int head2 = (head1 + perim / 2) % perim;

    int rip_radius = -1;
    if (phase == UI_PROMPT && ctx->ripple_start_ms > 0 &&
        t_now >= ctx->ripple_start_ms && (t_now - ctx->ripple_start_ms) < 320) {
        rip_radius = (int)(((t_now - ctx->ripple_start_ms) * (uint64_t)(cur_inner_w / 2 + 4)) / 320ULL);
    }

    int title_start = (cur_inner_w - title_len) / 2;
    enum color_id corner_base = (border_base == COL_SOFT_WHITE) ? COL_WHITE : border_base;

    put_cell(box_row, cur_box_col, rows, cols, "┌",
             comet_border_color(0, perim, head1, head2, corner_base));

    for (int i = 0; i < cur_inner_w; i++) {
        int dist_center = i - cur_inner_w / 2;
        if (dist_center < 0)
            dist_center = -dist_center;

        enum color_id cc = comet_border_color(1 + i, perim, head1, head2, border_base);
        if (rip_radius >= 0 && dist_center >= rip_radius - 2 && dist_center <= rip_radius + 2 &&
            border_base == COL_SOFT_WHITE) {
            cc = (dist_center == rip_radius) ? COL_WHITE : COL_BRIGHT_MINT;
        }

        if (cur_inner_w == inner_w && i >= title_start && i - title_start < title_len) {
            enum color_id tc = COL_WHITE;
            if (border_base == COL_RED)
                tc = COL_RED;
            else if (border_base == COL_EMERALD)
                tc = COL_SOFT_WHITE;
            else if (cc == COL_BRIGHT_MINT || (rip_radius >= 0 && dist_center <= rip_radius + 1))
                tc = COL_BRIGHT_MINT;
            put_cell(box_row, cur_box_col + 1 + i, rows, cols, title_cells[i - title_start], tc);
        } else {
            put_cell(box_row, cur_box_col + 1 + i, rows, cols, "─", cc);
        }
    }

    put_cell(box_row, cur_box_col + cur_inner_w + 1, rows, cols, "┐",
             comet_border_color(cur_inner_w + 1, perim, head1, head2, corner_base));

    enum color_id right_c = comet_border_color(cur_inner_w + 2, perim, head1, head2, border_base);
    enum color_id left_c  = comet_border_color(2 * cur_inner_w + 5, perim, head1, head2, border_base);
    if (rip_radius >= cur_inner_w / 2 - 1 && border_base == COL_SOFT_WHITE) {
        right_c = COL_BRIGHT_MINT;
        left_c = COL_BRIGHT_MINT;
    }

    put_cell(box_row + 1, cur_box_col, rows, cols, "│", left_c);

    if (phase == UI_GRANTED) {
        const char *ok_msg = "« ACCESS GRANTED · VOLUME UNLOCKED »";
        int olen = utf8_display_cols(ok_msg);
        int pad = (cur_inner_w - olen) / 2;
        if (pad < 0)
            pad = 0;
        put_utf8_str(box_row + 1, cur_box_col + 1 + pad, rows, cols, ok_msg, COL_EMERALD);
    } else if (phase == UI_UNLOCKING) {
        int s = fast_sin((int)((phase_elapsed_ms * 64ULL) / 1300ULL));
        int pos = ((s + 256) * (cur_inner_w - 1) + 256) / 512;
        for (int i = 0; i < cur_inner_w; i++) {
            int d = i - pos;
            if (d < 0)
                d = -d;
            if (d == 0)
                put_cell(box_row + 1, cur_box_col + 1 + i, rows, cols, "█", COL_WHITE);
            else if (d <= 2)
                put_cell(box_row + 1, cur_box_col + 1 + i, rows, cols, "▓", COL_BRIGHT_MINT);
            else if (d <= 5)
                put_cell(box_row + 1, cur_box_col + 1 + i, rows, cols, "▒", COL_ACCENT_TEAL);
            else if (d <= 8)
                put_cell(box_row + 1, cur_box_col + 1 + i, rows, cols, "░", COL_DEEP_TEAL);
        }
    } else if (cur_inner_w == inner_w) {
        bool has_typed = (typed_glyph_count > 0);
        bool blink_hi = ((t_now / 420ULL) % 2ULL) == 0;
        enum color_id cur_col = (rip_radius >= 0 || has_typed) ? COL_BRIGHT_MINT : COL_ACCENT_TEAL;
        if (cfg->pw_mode == PW_MASKED || cfg->pw_mode == PW_BLOCKS) {
            const char *mask_glyph = (cfg->pw_mode == PW_BLOCKS) ? "■" : "•";
            int max_vis = cur_inner_w - 4;
            if (max_vis < 1)
                max_vis = 1;
            int vis_count = (typed_glyph_count > (size_t)max_vis)
                                ? max_vis
                                : (int)typed_glyph_count;
            for (int m = 0; m < vis_count; m++) {
                enum color_id mc = (m == vis_count - 1 && rip_radius >= 0)
                                       ? COL_BRIGHT_MINT
                                       : COL_ACCENT_TEAL;
                put_cell(box_row + 1, cur_box_col + 2 + m, rows, cols, mask_glyph, mc);
            }
            const char *cur_glyph = blink_hi ? "█" : "▓";
            int cur_x = cur_box_col + 2 + (vis_count < max_vis ? vis_count : max_vis);
            put_cell(box_row + 1, cur_x, rows, cols, cur_glyph, cur_col);
        } else if (cfg->pw_mode == PW_PULSE) {
            const char *cur_glyph = has_typed ? (blink_hi ? "█" : "▓") : (blink_hi ? "▓" : "▒");
            put_cell(box_row + 1, cur_box_col + 2, rows, cols, cur_glyph, cur_col);
        } else if (!has_typed) {
            const char *cur_glyph = blink_hi ? "▒" : "░";
            put_cell(box_row + 1, cur_box_col + 2, rows, cols, cur_glyph, COL_DIM_GRAY);
        }
    }

    put_cell(box_row + 1, cur_box_col + cur_inner_w + 1, rows, cols, "│", right_c);

    put_cell(box_row + 2, cur_box_col, rows, cols, "└",
             comet_border_color(2 * cur_inner_w + 4, perim, head1, head2, corner_base));

    for (int i = 0; i < cur_inner_w; i++) {
        int dist_center = i - cur_inner_w / 2;
        if (dist_center < 0)
            dist_center = -dist_center;

        int perim_idx = cur_inner_w + 4 + (cur_inner_w - 1 - i);
        enum color_id cc = comet_border_color(perim_idx, perim, head1, head2, border_base);
        if (rip_radius >= 0 && dist_center >= rip_radius - 2 && dist_center <= rip_radius + 2 &&
            border_base == COL_SOFT_WHITE) {
            cc = (dist_center == rip_radius) ? COL_WHITE : COL_BRIGHT_MINT;
        }
        put_cell(box_row + 2, cur_box_col + 1 + i, rows, cols, "─", cc);
    }

    put_cell(box_row + 2, cur_box_col + cur_inner_w + 1, rows, cols, "┘",
             comet_border_color(cur_inner_w + 3, perim, head1, head2, corner_base));

    if (box_row + 4 < rows) {
        if (phase == UI_UNLOCKING) {
            const char *umsg = "Unlocking volume (verifying keyslot)...";
            int ulen = utf8_display_cols(umsg);
            put_utf8_str(box_row + 4, (cols - ulen) / 2, rows, cols, umsg, COL_ACCENT_TEAL);
        } else if (phase == UI_PROMPT && show_err) {
            const char *emsg = "Incorrect passphrase, try again.";
            int elen = utf8_display_cols(emsg);
            put_utf8_str(box_row + 4, (cols - elen) / 2 + shake_dx, rows, cols, emsg, COL_RED);
        } else if (phase == UI_PROMPT && is_capslock_on(tty_fd, ctx->is_linux_vt)) {
            const char *cmsg = "[ CAPS LOCK ON ]";
            int clen = utf8_display_cols(cmsg);
            put_utf8_str(box_row + 4, (cols - clen) / 2, rows, cols, cmsg, COL_RED);
        }
    }

    if (is_preview && rows >= 18) {
        const char *hud =
            "[PREVIEW]  [Type] Input  [Bksp/Ctrl+U] Clear  [Enter] Unlock  [Ctrl+E] Error  [Ctrl+R] Intro  [Esc] Quit";
        int hlen = utf8_display_cols(hud);
        int hcol = (cols - hlen) / 2;
        if (hcol < 0)
            hcol = 0;
        put_utf8_str(rows - 1, hcol, rows, cols, hud, COL_DIM_GRAY);
    }

    size_t pos = 0;
    if (!ctx->is_linux_vt)
        pos += (size_t)snprintf(g_outbuf + pos, sizeof(g_outbuf) - pos, "\033[?2026h");
    pos += (size_t)snprintf(g_outbuf + pos, sizeof(g_outbuf) - pos, "\033[?7l\033[?25l\033[0m");

    size_t row_bytes = (size_t)cols * sizeof(struct cell);
    bool any_row_written = false;

    for (int r = 0; r < rows; r++) {
        if (!ctx->force_full_redraw &&
            memcmp(&g_canvas[r][0], &g_prev_canvas[r][0], row_bytes) == 0) {
            continue;
        }
        memcpy(&g_prev_canvas[r][0], &g_canvas[r][0], row_bytes);
        any_row_written = true;

        if (pos + 32 >= sizeof(g_outbuf))
            break;
        pos += (size_t)snprintf(g_outbuf + pos, sizeof(g_outbuf) - pos, "\033[%d;1H", r + 1);

        int last_non_space = -1;
        for (int c = cols - 1; c >= 0; c--) {
            if (!(g_canvas[r][c].utf8[0] == ' ' && g_canvas[r][c].utf8[1] == '\0')) {
                last_non_space = c;
                break;
            }
        }

        enum color_id cur_color = COL_DEFAULT;
        for (int c = 0; c <= last_non_space; c++) {
            const struct cell *cl = &g_canvas[r][c];
            if ((enum color_id)cl->color != cur_color) {
                const char *cs = color_seq((enum color_id)cl->color, ctx->is_linux_vt, cfg);
                size_t cslen = strlen(cs);
                if (pos + cslen + 24 < sizeof(g_outbuf)) {
                    memcpy(g_outbuf + pos, cs, cslen);
                    pos += cslen;
                }
                cur_color = (enum color_id)cl->color;
            }
            size_t glen = strlen(cl->utf8);
            if (pos + glen + 24 < sizeof(g_outbuf)) {
                memcpy(g_outbuf + pos, cl->utf8, glen);
                pos += glen;
            }
        }
        if (cur_color != COL_DEFAULT && pos + 16 < sizeof(g_outbuf)) {
            memcpy(g_outbuf + pos, "\033[0m", 4);
            pos += 4;
        }
        if (last_non_space < cols - 1 && pos + 16 < sizeof(g_outbuf)) {
            memcpy(g_outbuf + pos, "\033[K", 3);
            pos += 3;
        }
    }

    if (!ctx->is_linux_vt && pos + 12 < sizeof(g_outbuf))
        pos += (size_t)snprintf(g_outbuf + pos, sizeof(g_outbuf) - pos, "\033[?2026l");

    ctx->force_full_redraw = false;
    if (any_row_written)
        (void)write_all(tty_fd, g_outbuf, pos);
}

static void drain_escape_sequence(int tty_fd) {
    struct pollfd pfd = {.fd = tty_fd, .events = POLLIN};
    char ch = 0;
    for (int i = 0; i < 12; i++) {
        if (poll(&pfd, 1, 20) <= 0)
            break;
        if (read(tty_fd, &ch, 1) != 1)
            break;
        if (i >= 1 && (unsigned char)ch >= 0x40 && (unsigned char)ch <= 0x7e)
            break;
    }
    explicit_bzero(&ch, sizeof(ch));
}

static size_t pop_last_utf8_char(char *buf, size_t len) {
    if (len == 0)
        return 0;
    size_t i = len - 1;
    while (i > 0 && ((unsigned char)buf[i] & 0xC0) == 0x80) {
        buf[i] = '\0';
        i--;
    }
    buf[i] = '\0';
    return i;
}

static void drain_inotify(int inotify_fd) {
    char evbuf[2048] __attribute__((aligned(__alignof__(struct inotify_event))));
    while (read(inotify_fd, evbuf, sizeof(evbuf)) > 0) {
    }
}

static void discard_tty_input(int tty_fd) {
    struct pollfd kpfd = {.fd = tty_fd, .events = POLLIN};
    char sink[64];
    while (poll(&kpfd, 1, 0) > 0 && (kpfd.revents & POLLIN)) {
        if (read(tty_fd, sink, sizeof(sink)) <= 0)
            break;
    }
    explicit_bzero(sink, sizeof(sink));
}

static int send_passphrase_reply(
    const char *socket_path,
    const char *ask_dir,
    bool custom_env,
    const char *pass,
    size_t pass_len
) {
    if (!is_trusted_socket(socket_path, ask_dir, custom_env))
        return -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    size_t slen = strlen(socket_path);
    if (slen == 0 || slen >= sizeof(sa.sun_path))
        return -1;
    memcpy(sa.sun_path, socket_path, slen);
    socklen_t addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + slen + 1);

    g_secret.pkt[0] = '+';
    if (pass_len > 0)
        memcpy(g_secret.pkt + 1, pass, pass_len);

    int sfd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int rc = -1;
    if (sfd >= 0) {
        ssize_t sent = sendto(sfd, g_secret.pkt, pass_len + 1, MSG_NOSIGNAL,
                              (const struct sockaddr *)&sa, addrlen);
        if (sent == (ssize_t)(pass_len + 1))
            rc = 0;
        close(sfd);
    }

    explicit_bzero(g_secret.pkt, sizeof(g_secret.pkt));
    return rc;
}

enum prompt_result {
    PROMPT_SUBMITTED = 0,
    PROMPT_VANISHED  = 1,
    PROMPT_STOPPED   = 2,
};

static enum prompt_result prompt_user_on_tty(
    struct tty_session *tty,
    int inotify_fd,
    struct anim_ctx *ctx,
    const struct ui_config *cfg,
    const struct ask_request *req,
    const char *ask_dir,
    bool custom_env,
    bool show_retry_err
) {
    if (!tty->is_raw) {
        tty_enter_raw(tty, cfg);
        ctx->force_full_redraw = true;
    }

    explicit_bzero(g_secret.pass, sizeof(g_secret.pass));
    size_t pass_len = 0;

    bool err_visible = show_retry_err;
    if (show_retry_err) {
        ctx->error_start_ms = now_ms();
        ctx->last_input_ms = ctx->error_start_ms;
    }

    int drawn_rows = 0, drawn_cols = 0;
    int settle_ticks = 0;
    uint64_t last_palette_ms = now_ms();

    render_frame(tty->fd, ctx, cfg, req->prompt_title, 0, err_visible, false,
                 UI_PROMPT, 0, &drawn_rows, &drawn_cols);

    enum prompt_result res = PROMPT_STOPPED;
    char ch = 0;

    while (!g_stop) {
        int cur_rows = 0, cur_cols = 0;
        get_term_size(tty->fd, &cur_rows, &cur_cols);

        if (g_winch || cur_rows != drawn_rows || cur_cols != drawn_cols) {
            g_winch = 0;
            tty_reassert_raw(tty, cfg);
            write_str(tty->fd, "\033[2J\033[H");
            ctx->force_full_redraw = true;
            ctx->last_input_ms = now_ms();
            last_palette_ms = ctx->last_input_ms;
            settle_ticks = 6;
        } else if (settle_ticks > 0) {
            settle_ticks--;
            if (settle_ticks == 0) {
                tty_reassert_raw(tty, cfg);
                ctx->force_full_redraw = true;
            }
        }

        if (access(req->ask_path, F_OK) != 0 || is_request_expired(req)) {
            res = PROMPT_VANISHED;
            break;
        }

        uint64_t t_now = now_ms();
        if (tty->is_linux_vt && t_now >= last_palette_ms + 1500ULL) {
            apply_vt_palette(tty->fd, true, cfg);
            last_palette_ms = t_now;
        }
        int timeout_ms = (cfg->idle_after_ms > 0 && t_now >= ctx->last_input_ms &&
                          (t_now - ctx->last_input_ms) > cfg->idle_after_ms)
                             ? IDLE_FRAME_MS
                             : ACTIVE_FRAME_MS;

        struct pollfd pfds[2] = {
            {.fd = tty->fd, .events = POLLIN},
            {.fd = inotify_fd, .events = POLLIN},
        };
        int prc = poll(pfds, 2, timeout_ms);
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (prc > 0 && (pfds[1].revents & POLLIN)) {
            drain_inotify(inotify_fd);
            if (access(req->ask_path, F_OK) != 0 || is_request_expired(req)) {
                res = PROMPT_VANISHED;
                break;
            }
        }

        if (prc > 0 && (pfds[0].revents & POLLIN)) {
            struct pollfd kpfd = {.fd = tty->fd, .events = POLLIN};
            bool submitted_now = false;
            while (poll(&kpfd, 1, 0) > 0 && (kpfd.revents & POLLIN)) {
                ssize_t n = read(tty->fd, &ch, 1);
                if (n <= 0)
                    break;

                unsigned char uch = (unsigned char)ch;
                ctx->last_input_ms = now_ms();

                if (uch == '\r' || uch == '\n') {
                    size_t gcount = count_utf8_chars(g_secret.pass, pass_len);
                    render_frame(tty->fd, ctx, cfg, req->prompt_title, gcount,
                                 false, false, UI_UNLOCKING, 0, &drawn_rows, &drawn_cols);
                    if (send_passphrase_reply(req->socket_path, ask_dir, custom_env,
                                              g_secret.pass, pass_len) == 0) {
                        res = PROMPT_SUBMITTED;
                        submitted_now = true;
                        break;
                    }
                    explicit_bzero(g_secret.pass, sizeof(g_secret.pass));
                    pass_len = 0;
                    err_visible = true;
                    ctx->error_start_ms = ctx->last_input_ms;
                } else if (uch == 0x7f || uch == 0x08) {
                    if (pass_len > 0) {
                        pass_len = pop_last_utf8_char(g_secret.pass, pass_len);
                        ctx->ripple_start_ms = ctx->last_input_ms;
                    }
                } else if (uch == 0x15) {
                    explicit_bzero(g_secret.pass, sizeof(g_secret.pass));
                    pass_len = 0;
                    ctx->ripple_start_ms = ctx->last_input_ms;
                } else if (uch == 0x1b) {
                    drain_escape_sequence(tty->fd);
                } else if (uch >= 0x20) {
                    err_visible = false;
                    ctx->error_start_ms = 0;
                    ctx->ripple_start_ms = ctx->last_input_ms;
                    if (pass_len < MAX_PASS_LEN) {
                        g_secret.pass[pass_len++] = ch;
                        g_secret.pass[pass_len] = '\0';
                    }
                }
            }
            if (submitted_now)
                break;
        }

        render_frame(tty->fd, ctx, cfg, req->prompt_title,
                     count_utf8_chars(g_secret.pass, pass_len),
                     err_visible, false, UI_PROMPT, 0, &drawn_rows, &drawn_cols);
    }

    explicit_bzero(&ch, sizeof(ch));
    explicit_bzero(g_secret.pass, sizeof(g_secret.pass));
    return res;
}

/* systemd-cryptsetup unlinks ask.* immediately on datagram receipt, then runs Argon2id
 * inside req->pid; keep scanner visible until req->pid exits or drops a retry ask.*. */
static void await_verification_and_grant(
    struct tty_session *tty,
    int inotify_fd,
    struct anim_ctx *ctx,
    const struct ui_config *cfg,
    const struct ask_request *submitted,
    const char *ask_dir,
    const char *mapper_dir,
    bool custom_env,
    bool check_mapper,
    bool watch_mode,
    int mapper_before
) {
    uint64_t t_start = now_ms();
    uint64_t min_scan = (ctx->skip_intro && !watch_mode) ? FAST_SCANNER_MS : MIN_SCANNER_MS;
    bool is_retry = false;

    while (!g_stop) {
        uint64_t elapsed = (now_ms() >= t_start) ? (now_ms() - t_start) : 0;
        if (elapsed >= MAX_UNLOCK_WAIT_MS)
            return;

        struct ask_request next_req;
        if (find_pending_request(ask_dir, custom_env, submitted->ask_path, &next_req)) {
            is_retry = true;
            break;
        }

        bool querier_busy = (watch_mode || check_mapper) &&
                            (access(submitted->ask_path, F_OK) == 0 ||
                             (submitted->pid > 0 && kill(submitted->pid, 0) == 0));

        if (!querier_busy && elapsed >= min_scan)
            break;

        render_frame(tty->fd, ctx, cfg, submitted->prompt_title, 1, false, false,
                     UI_UNLOCKING, elapsed, NULL, NULL);

        struct pollfd pfds[2] = {
            {.fd = inotify_fd, .events = POLLIN},
            {.fd = tty->fd, .events = POLLIN},
        };
        int prc = poll(pfds, 2, ACTIVE_FRAME_MS);
        if (prc > 0) {
            if (pfds[0].revents & POLLIN)
                drain_inotify(inotify_fd);
            if (pfds[1].revents & POLLIN)
                discard_tty_input(tty->fd);
        }
    }

    if (is_retry)
        return;

    struct ask_request late_req;
    if (find_pending_request(ask_dir, custom_env, submitted->ask_path, &late_req)) {
        return;
    }

    if (check_mapper && strncmp(submitted->id, "cryptsetup:", 11) == 0) {
        int mapper_now = count_mapper_targets(mapper_dir);
        if (mapper_now <= mapper_before)
            return;
    }

    uint64_t grant_start = now_ms();
    uint64_t grant_hold = (ctx->skip_intro && !watch_mode) ? FAST_GRANTED_MS : GRANTED_HOLD_MS;
    while (true) {
        uint64_t dt = (now_ms() >= grant_start) ? (now_ms() - grant_start) : 0;
        render_frame(tty->fd, ctx, cfg, submitted->prompt_title, 1, false, false,
                     UI_GRANTED, dt, NULL, NULL);
        if (dt >= grant_hold)
            break;
        struct pollfd pfd = {.fd = tty->fd, .events = POLLIN};
        if (poll(&pfd, 1, ACTIVE_FRAME_MS) > 0 && (pfd.revents & POLLIN))
            discard_tty_input(tty->fd);
    }
}

static int run_preview_mode(
    struct tty_session *tty,
    struct anim_ctx *ctx,
    const struct ui_config *cfg
) {
    tty_enter_raw(tty, cfg);
    ctx->force_full_redraw = true;

    explicit_bzero(g_secret.pass, sizeof(g_secret.pass));
    size_t pass_len = 0;
    uint64_t unlock_start = 0;
    bool err_visible = false;
    int drawn_rows = 0, drawn_cols = 0;
    const char *preview_title = " Enter passphrase for /dev/nvme0n1p2: ";

    while (!g_stop) {
        uint64_t t_now = now_ms();
        int cur_rows = 0, cur_cols = 0;
        get_term_size(tty->fd, &cur_rows, &cur_cols);
        if (g_winch || cur_rows != drawn_rows || cur_cols != drawn_cols) {
            g_winch = 0;
            tty_reassert_raw(tty, cfg);
            write_str(tty->fd, "\033[2J\033[H");
            ctx->force_full_redraw = true;
        }

        enum ui_phase phase = UI_PROMPT;
        uint64_t phase_dt = 0;
        if (unlock_start > 0 && t_now >= unlock_start) {
            uint64_t dt = t_now - unlock_start;
            if (dt < 1300ULL) {
                phase = UI_UNLOCKING;
                phase_dt = dt;
            } else if (dt < 2400ULL) {
                phase = UI_GRANTED;
                phase_dt = dt - 1300ULL;
            } else {
                unlock_start = 0;
                explicit_bzero(g_secret.pass, sizeof(g_secret.pass));
                pass_len = 0;
            }
        }

        render_frame(tty->fd, ctx, cfg, preview_title,
                     count_utf8_chars(g_secret.pass, pass_len),
                     err_visible, true, phase, phase_dt, &drawn_rows, &drawn_cols);

        struct pollfd pfd = {.fd = tty->fd, .events = POLLIN};
        int prc = poll(&pfd, 1, ACTIVE_FRAME_MS);
        if (prc > 0 && (pfd.revents & POLLIN)) {
            char ch = 0;
            while (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
                if (read(tty->fd, &ch, 1) != 1)
                    break;
                unsigned char uch = (unsigned char)ch;
                ctx->last_input_ms = now_ms();
                if (uch == 0x03 || uch == 0x11) {
                    g_stop = 1;
                    break;
                } else if (uch == 0x1b) {
                    if (poll(&pfd, 1, 20) > 0) {
                        drain_escape_sequence(tty->fd);
                    } else {
                        g_stop = 1;
                        break;
                    }
                } else if (uch == 0x12) {
                    ctx->skip_intro = false;
                    ctx->intro_start_ms = ctx->last_input_ms;
                    unlock_start = 0;
                    err_visible = false;
                    ctx->error_start_ms = 0;
                } else if (uch == 0x05) {
                    unlock_start = 0;
                    err_visible = true;
                    ctx->error_start_ms = ctx->last_input_ms;
                } else if (uch == '\r' || uch == '\n') {
                    unlock_start = ctx->last_input_ms;
                    err_visible = false;
                    ctx->error_start_ms = 0;
                } else if (uch == 0x7f || uch == 0x08) {
                    if (pass_len > 0) {
                        pass_len = pop_last_utf8_char(g_secret.pass, pass_len);
                        ctx->ripple_start_ms = ctx->last_input_ms;
                    }
                } else if (uch == 0x15) {
                    explicit_bzero(g_secret.pass, sizeof(g_secret.pass));
                    pass_len = 0;
                    ctx->ripple_start_ms = ctx->last_input_ms;
                } else if (uch >= 0x20 && phase == UI_PROMPT) {
                    err_visible = false;
                    ctx->error_start_ms = 0;
                    ctx->ripple_start_ms = ctx->last_input_ms;
                    if (pass_len < MAX_PASS_LEN) {
                        g_secret.pass[pass_len++] = ch;
                        g_secret.pass[pass_len] = '\0';
                    }
                }
            }
            explicit_bzero(&ch, sizeof(ch));
        }
    }

    tty_restore(tty);
    wipe_secrets();
    return 0;
}

static void fallback_to_stock_agent(bool watch_mode) {
    if (access(FALLBACK_AGENT, X_OK) == 0) {
        execl(FALLBACK_AGENT, "systemd-tty-ask-password-agent",
              watch_mode ? "--watch" : "--query", "--console", (char *)NULL);
    }
}

int main(int argc, char *argv[]) {
    harden_process_memory();
    atexit(wipe_secrets);

    bool watch_mode = false;
    bool preview_mode = false;
    bool custom_env = false;
    bool have_custom_mapper = false;
    bool cli_no_intro = false;
    bool have_cli_accent = false;
    struct rgb cli_accent = {0, 0, 0};

    const char *ask_dir = DEFAULT_ASK_DIR;
    const char *mapper_dir = DEFAULT_MAPPER_DIR;
    const char *conf_path = DEFAULT_CONF_PATH;
    const char *explicit_tty = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--watch") == 0) {
            watch_mode = true;
        } else if (strcmp(argv[i], "--query") == 0) {
            watch_mode = false;
        } else if (strcmp(argv[i], "--preview") == 0) {
            preview_mode = true;
            custom_env = true;
        } else if (strcmp(argv[i], "--no-intro") == 0) {
            cli_no_intro = true;
        } else if (strcmp(argv[i], "--console") == 0) {
            continue;
        } else if (strncmp(argv[i], "--console=", 10) == 0) {
            explicit_tty = argv[i] + 10;
        } else if (strncmp(argv[i], "--tty=", 6) == 0) {
            explicit_tty = argv[i] + 6;
            custom_env = true;
        } else if (strncmp(argv[i], "--ask-dir=", 10) == 0) {
            ask_dir = argv[i] + 10;
            custom_env = true;
        } else if (strncmp(argv[i], "--mapper-dir=", 13) == 0) {
            mapper_dir = argv[i] + 13;
            custom_env = true;
            have_custom_mapper = true;
        } else if (strncmp(argv[i], "--config=", 9) == 0) {
            conf_path = argv[i] + 9;
            custom_env = true;
        } else if (strncmp(argv[i], "--accent=", 9) == 0) {
            if (parse_hex_rgb(argv[i] + 9, &cli_accent))
                have_cli_accent = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [--watch|--query|--preview] [--console[=DEV]] [--config=FILE] "
                   "[--accent=#RRGGBB] [--no-intro]\n", argv[0]);
            return 0;
        }
    }

    if (preview_mode && watch_mode) {
        fprintf(stderr, "archrelius-askpw: --preview cannot be combined with --watch\n");
        return 2;
    }

    struct ui_config cfg;
    init_default_config(&cfg);
    load_ui_config(&cfg, conf_path, custom_env);
    if (cli_no_intro)
        cfg.show_intro = false;
    if (have_cli_accent) {
        cfg.pal[COL_ACCENT_TEAL] = cli_accent;
        rebuild_pty_sgr(&cfg);
    }

    decode_banner_once();

    struct sigaction sa_stop, sa_winch, sa_ign;
    memset(&sa_stop, 0, sizeof(sa_stop));
    sa_stop.sa_handler = on_stop_signal;
    sigemptyset(&sa_stop.sa_mask);
    (void)sigaction(SIGTERM, &sa_stop, NULL);
    (void)sigaction(SIGINT, &sa_stop, NULL);
    (void)sigaction(SIGHUP, &sa_stop, NULL);
    (void)sigaction(SIGQUIT, &sa_stop, NULL);

    memset(&sa_winch, 0, sizeof(sa_winch));
    sa_winch.sa_handler = on_winch_signal;
    sigemptyset(&sa_winch.sa_mask);
    (void)sigaction(SIGWINCH, &sa_winch, NULL);

    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &sa_ign, NULL);
    (void)sigaction(SIGTSTP, &sa_ign, NULL);

    if (preview_mode) {
        int p_fd = -1;
        bool close_p_fd = false;
        if (explicit_tty && *explicit_tty) {
            p_fd = open(explicit_tty, O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
            close_p_fd = (p_fd >= 0);
        } else if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
            p_fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
            if (p_fd >= 0)
                close_p_fd = true;
            else
                p_fd = STDIN_FILENO;
        }
        if (p_fd < 0) {
            fprintf(stderr, "archrelius-askpw: --preview requires an interactive TTY\n");
            return 1;
        }
        struct anim_ctx p_ctx;
        init_anim_ctx(&p_ctx, p_fd, &cfg);
        struct tty_session p_tty = {
            .fd = p_fd,
            .have_orig = false,
            .is_raw = false,
            .is_linux_vt = p_ctx.is_linux_vt,
        };
        int rc = run_preview_mode(&p_tty, &p_ctx, &cfg);
        if (close_p_fd)
            close(p_fd);
        return rc;
    }

    (void)mkdir(ask_dir, 0755);

    int inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd < 0) {
        if (!custom_env)
            fallback_to_stock_agent(watch_mode);
        return 1;
    }

    if (inotify_add_watch(inotify_fd, ask_dir, IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE) < 0) {
        close(inotify_fd);
        if (!custom_env)
            fallback_to_stock_agent(watch_mode);
        return 1;
    }

    int tty_fd = open_console_tty(explicit_tty);
    if (tty_fd < 0) {
        close(inotify_fd);
        if (!custom_env)
            fallback_to_stock_agent(watch_mode);
        return 1;
    }

    struct anim_ctx ctx;
    init_anim_ctx(&ctx, tty_fd, &cfg);

    struct tty_session tty = {
        .fd = tty_fd,
        .have_orig = false,
        .is_raw = false,
        .is_linux_vt = ctx.is_linux_vt,
    };

    sd_notify_ready();

    char last_id[256] = {0};
    char last_submitted_path[PATH_MAX] = {0};
    int attempts_for_id = 0;
    bool check_mapper = (!custom_env || have_custom_mapper);

    while (!g_stop) {
        struct ask_request req;
        if (find_pending_request(ask_dir, custom_env, last_submitted_path, &req)) {
            last_submitted_path[0] = '\0';
            if (req.id[0] != '\0' && strcmp(req.id, last_id) == 0) {
                attempts_for_id++;
                ctx.skip_intro = true;
            } else {
                copy_str(last_id, sizeof(last_id), req.id);
                attempts_for_id = 0;
            }

            int mapper_before = count_mapper_targets(mapper_dir);
            enum prompt_result pr = prompt_user_on_tty(
                &tty, inotify_fd, &ctx, &cfg, &req, ask_dir, custom_env, attempts_for_id > 0);
            if (pr == PROMPT_SUBMITTED) {
                copy_str(last_submitted_path, sizeof(last_submitted_path), req.ask_path);
                await_verification_and_grant(
                    &tty, inotify_fd, &ctx, &cfg, &req, ask_dir, mapper_dir, custom_env,
                    check_mapper, watch_mode, mapper_before);
            }
            if (!watch_mode)
                break;
            continue;
        }

        if (tty.is_raw)
            tty_restore(&tty);

        if (!watch_mode)
            break;

        struct pollfd pfd = {.fd = inotify_fd, .events = POLLIN};
        int prc = poll(&pfd, 1, 250);
        if (prc > 0 && (pfd.revents & POLLIN))
            drain_inotify(inotify_fd);
    }

    tty_restore(&tty);
    wipe_secrets();
    close(tty_fd);
    close(inotify_fd);
    return 0;
}
