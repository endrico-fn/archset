/* SPDX-License-Identifier: MIT
 *
 * archrelius-askpw.c — Hardened Animated systemd Password Agent TUI
 * Implements https://systemd.io/PASSWORD_AGENTS/ for initramfs LUKS2 unlock.
 *
 * Visual & UX features:
 * - Cyan-kehijauan (#64beaf / #8ae3d2 / #235952) accent harmonized with
 *   KDE BreezeDarkMod & Kitty via Linux VT OSC P hardware palette programming
 *   (man 4 console_codes) on /dev/ttyN and 24-bit SGR on PTY terminals.
 * - 4 live Tab-switchable ASCII animation modes (Quantum Decrypt + Shimmer,
 *   Aurora Plasma + Stardust, Crypto Waterfall + Monolith, Minimal Telemetry).
 * - Live bidirectional Argon2id scanner while systemd-cryptsetup verifies key,
 *   keystroke border shockwave (zero character echo), and red shake on retry.
 * - Automatic KMS deferred-takeover recenter (160x50 -> 170x48) + idle battery
 *   throttle (drops from 30 FPS to 2 FPS after 15s of inactivity).
 *
 * Security & reliability properties:
 * - Pure glibc (libc.so.6 only; integer LUT trig & xorshift32 PRNG).
 * - Passphrase locked in RAM via mlock() and wiped via explicit_bzero().
 * - O_NOFOLLOW + S_ISREG + st_uid check on ask.* and S_ISSOCK + st_uid on Socket=.
 * - Automatic execl fallback to /usr/bin/systemd-tty-ask-password-agent on error.
 */

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
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/kd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ASK_DIR "/run/systemd/ask-password"
#define FALLBACK_AGENT  "/usr/bin/systemd-tty-ask-password-agent"
#define MAX_PASS_LEN    511
#define MAX_ROWS        120
#define MAX_COLS        320
#define BANNER_LINES    9
#define BANNER_WIDTH    116
#define ACTIVE_FRAME_MS 33
#define IDLE_FRAME_MS   500
#define IDLE_AFTER_MS   15000ULL
#define NUM_STARS       70

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

static const char *const MODE_LABELS[4] = {
    "« Theme 1/4: Quantum Shimmer »",
    "« Theme 2/4: Aurora Stardust »",
    "« Theme 3/4: Crypto Waterfall »",
    "« Theme 4/4: Minimal Telemetry »",
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
    COL_DIM_GRAY,     /* #465956 muted teal-slate */
    COL_DEEP_TEAL,    /* #235952 deep forest teal shadow */
    COL_MID_TEAL,     /* #3d8f83 mid seafoam teal */
    COL_CYAN_GREEN,   /* #52a899 rich cyan-green */
    COL_ACCENT_TEAL,  /* #64beaf primary BreezeDarkMod greenish-cyan accent */
    COL_BRIGHT_MINT,  /* #8ae3d2 bright mint-cyan highlight */
    COL_WHITE,        /* #ffffff crisp white */
    COL_SOFT_WHITE,   /* #d8e6e3 soft cool white */
    COL_RED,          /* #e06c75 coral red */
    COL_EMERALD,      /* #56b88d Kitty emerald accent */
};

struct cell {
    char utf8[5];
    enum color_id color;
};

struct banner_glyph {
    char utf8[5];
    bool is_edge;
};

struct drop {
    int row_fp;
    int speed_fp;
    int length;
    uint32_t seed;
};

struct star {
    int col_fp;
    int row_fp;
    int vx_fp;
    int vy_fp;
    uint8_t kind;
};

struct anim_ctx {
    int mode;
    int frame;
    bool is_linux_vt;
    bool skip_intro;
    uint32_t rng;
    uint64_t intro_start_ms;
    uint64_t ripple_start_ms;
    uint64_t error_start_ms;
    uint64_t mode_toast_ms;
    uint64_t last_input_ms;
    struct drop drops[MAX_COLS];
    struct star stars[NUM_STARS];
};

struct ask_request {
    char ask_path[PATH_MAX];
    char socket_path[PATH_MAX];
    char id[256];
    char message[256];
    char dev_label[128];
    pid_t pid;
    uint64_t not_after_usec;
};

static struct banner_glyph g_banner[BANNER_LINES][BANNER_WIDTH];
static struct cell g_canvas[MAX_ROWS][MAX_COLS];
static char g_outbuf[MAX_ROWS * MAX_COLS * 20];

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_winch = 0;

static inline int fast_sin(int idx) {
    return SIN64[idx & 63];
}

static uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void on_stop_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void on_winch_signal(int sig) {
    (void)sig;
    g_winch = 1;
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
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

/* Program Linux VT 16-color palette slots to exact #64beaf greenish-cyan RGB */
static void apply_vt_palette(int tty_fd, bool is_linux_vt) {
    if (!is_linux_vt)
        return;
    static const char pal_seq[] =
        "\033]P4235952"  /* slot 4  (34m):  deep teal #235952 */
        "\033]P664beaf"  /* slot 6  (36m):  primary greenish-cyan #64beaf */
        "\033]P8465956"  /* slot 8  (90m):  muted teal-slate #465956 */
        "\033]P9e06c75"  /* slot 9  (1;31m): coral red #e06c75 */
        "\033]PA56b88d"  /* slot 10 (1;32m): Kitty emerald #56b88d */
        "\033]PC3d8f83"  /* slot 12 (1;34m): mid seafoam #3d8f83 */
        "\033]PE8ae3d2"; /* slot 14 (1;36m): bright mint-cyan #8ae3d2 */
    (void)write_all(tty_fd, pal_seq, sizeof(pal_seq) - 1);
}

static const char *color_seq(enum color_id c, bool is_linux_vt) {
    if (is_linux_vt) {
        switch (c) {
            case COL_DIM_GRAY:    return "\033[0;90m";
            case COL_DEEP_TEAL:   return "\033[0;34m";
            case COL_MID_TEAL:    return "\033[1;34m";
            case COL_CYAN_GREEN:  return "\033[0;36m";
            case COL_ACCENT_TEAL: return "\033[0;36m";
            case COL_BRIGHT_MINT: return "\033[1;36m";
            case COL_WHITE:       return "\033[1;37m";
            case COL_SOFT_WHITE:  return "\033[0;37m";
            case COL_RED:         return "\033[1;31m";
            case COL_EMERALD:     return "\033[1;32m";
            default:              return "\033[0m";
        }
    }
    switch (c) {
        case COL_DIM_GRAY:    return "\033[38;2;70;89;86m";
        case COL_DEEP_TEAL:   return "\033[38;2;35;89;82m";
        case COL_MID_TEAL:    return "\033[38;2;61;143;131m";
        case COL_CYAN_GREEN:  return "\033[38;2;82;168;153m";
        case COL_ACCENT_TEAL: return "\033[1;38;2;100;190;175m";
        case COL_BRIGHT_MINT: return "\033[1;38;2;138;227;210m";
        case COL_WHITE:       return "\033[1;38;2;255;255;255m";
        case COL_SOFT_WHITE:  return "\033[38;2;216;230;227m";
        case COL_RED:         return "\033[1;38;2;224;108;117m";
        case COL_EMERALD:     return "\033[1;38;2;86;184;141m";
        default:              return "\033[0m";
    }
}

static void decode_banner_once(void) {
    for (int r = 0; r < BANNER_LINES; r++) {
        for (int c = 0; c < BANNER_WIDTH; c++) {
            strcpy(g_banner[r][c].utf8, " ");
            g_banner[r][c].is_edge = false;
        }
        const unsigned char *p = (const unsigned char *)BANNER_RAW[r];
        int col = 0;
        while (*p && col < BANNER_WIDTH) {
            size_t clen = 1;
            if ((*p & 0xE0) == 0xC0)
                clen = 2;
            else if ((*p & 0xF0) == 0xE0)
                clen = 3;
            else if ((*p & 0xF8) == 0xF0)
                clen = 4;

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

static void init_anim_ctx(struct anim_ctx *ctx, int tty_fd, bool skip_intro) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->mode = 0;
    ctx->skip_intro = skip_intro;
    ctx->rng = 0xA4C82026U ^ (uint32_t)getpid();
    uint64_t t = now_ms();
    ctx->intro_start_ms = t;
    ctx->last_input_ms = t;

    long kd_mode = 0;
    ctx->is_linux_vt = (ioctl(tty_fd, KDGETMODE, &kd_mode) == 0);

    for (int i = 0; i < MAX_COLS; i++) {
        ctx->drops[i].row_fp = -(int)(xorshift32(&ctx->rng) % 600);
        ctx->drops[i].speed_fp = 5 + (int)(xorshift32(&ctx->rng) % 9);
        ctx->drops[i].length = 6 + (int)(xorshift32(&ctx->rng) % 12);
        ctx->drops[i].seed = xorshift32(&ctx->rng);
    }
    for (int i = 0; i < NUM_STARS; i++) {
        ctx->stars[i].col_fp = (int)(xorshift32(&ctx->rng) % (200 * 16));
        ctx->stars[i].row_fp = (int)(xorshift32(&ctx->rng) % (60 * 16));
        ctx->stars[i].vx_fp = 1 + (int)(xorshift32(&ctx->rng) % 3);
        ctx->stars[i].vy_fp = -1 - (int)(xorshift32(&ctx->rng) % 2);
        ctx->stars[i].kind = (uint8_t)(xorshift32(&ctx->rng) % 4);
    }
}

static void sd_notify_ready(void) {
    const char *sock = getenv("NOTIFY_SOCKET");
    if (!sock || !*sock)
        return;
    if (sock[0] != '/' && sock[0] != '@')
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
    snprintf(out, out_sz, "%s", last);
    return true;
}

static int open_console_tty(const char *explicit_tty) {
    if (explicit_tty && *explicit_tty)
        return open(explicit_tty, O_RDWR | O_NOCTTY | O_CLOEXEC);

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
        int fd = open(devpath, O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (fd >= 0)
            return fd;
    }

    static const char *const candidates[] = {"/dev/tty1", "/dev/tty0", "/dev/console"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        int fd = open(candidates[i], O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (fd >= 0)
            return fd;
    }
    return -1;
}

static void trim_right(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t'))
        s[--len] = '\0';
}

static void derive_device_label(const struct ask_request *req, char *out, size_t out_sz) {
    if (strncmp(req->id, "cryptsetup:", 11) == 0) {
        const char *src = req->id + 11;
        char resolved[PATH_MAX];
        if (realpath(src, resolved) != NULL) {
            snprintf(out, out_sz, "%.*s", (int)(out_sz - 1), resolved);
            return;
        }
        if (*src) {
            snprintf(out, out_sz, "%.*s", (int)(out_sz - 1), src);
            return;
        }
    }
    snprintf(out, out_sz, "/dev/mapper/root");
}

static bool is_trusted_socket(const char *socket_path) {
    struct stat st;
    if (!socket_path || !*socket_path)
        return false;
    if (stat(socket_path, &st) < 0)
        return false;
    return S_ISSOCK(st.st_mode) && (st.st_uid == geteuid());
}

static bool parse_ask_file(const char *ask_path, struct ask_request *req) {
    int fd = open(ask_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return false;

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
        close(fd);
        return false;
    }

    FILE *fp = fdopen(fd, "r");
    if (!fp) {
        close(fd);
        return false;
    }

    memset(req, 0, sizeof(*req));
    snprintf(req->ask_path, sizeof(req->ask_path), "%.*s",
             (int)(sizeof(req->ask_path) - 1), ask_path);

    bool in_ask = false;
    char line[1024];
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_right(line);
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
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
        const char *key = p;
        const char *val = eq + 1;

        if (strcmp(key, "Socket") == 0) {
            snprintf(req->socket_path, sizeof(req->socket_path), "%.*s",
                     (int)(sizeof(req->socket_path) - 1), val);
        } else if (strcmp(key, "Id") == 0) {
            snprintf(req->id, sizeof(req->id), "%.*s",
                     (int)(sizeof(req->id) - 1), val);
        } else if (strcmp(key, "Message") == 0) {
            snprintf(req->message, sizeof(req->message), "%.*s",
                     (int)(sizeof(req->message) - 1), val);
        } else if (strcmp(key, "PID") == 0) {
            req->pid = (pid_t)strtol(val, NULL, 10);
        } else if (strcmp(key, "NotAfter") == 0) {
            req->not_after_usec = (uint64_t)strtoull(val, NULL, 10);
        }
    }
    fclose(fp);

    if (!is_trusted_socket(req->socket_path))
        return false;
    if (req->not_after_usec > 0) {
        uint64_t now = now_monotonic_usec();
        if (now > 0 && now > req->not_after_usec)
            return false;
    }
    if (req->pid > 0 && kill(req->pid, 0) < 0 && errno == ESRCH)
        return false;

    derive_device_label(req, req->dev_label, sizeof(req->dev_label));
    return true;
}

static bool find_pending_request(const char *ask_dir, struct ask_request *req) {
    DIR *dir = opendir(ask_dir);
    if (!dir)
        return false;

    bool found = false;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, "ask.", 4) != 0)
            continue;
        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s/%s", ask_dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(full))
            continue;
        if (parse_ask_file(full, req)) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
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
    snprintf(g_canvas[r][c].utf8, sizeof(g_canvas[r][c].utf8), "%s", glyph);
    g_canvas[r][c].color = col_id;
}

static void put_ascii_str(int r, int c, int rows, int cols, const char *s, enum color_id col_id) {
    for (int i = 0; s[i] != '\0'; i++) {
        char tmp[2] = {s[i], '\0'};
        put_cell(r, c + i, rows, cols, tmp, col_id);
    }
}

static void render_frame(
    int tty_fd,
    struct anim_ctx *ctx,
    const char *dev_label,
    bool show_err,
    bool unlocking_bar,
    uint64_t unlock_elapsed_ms,
    int *out_rows,
    int *out_cols
) {
    static const char *const CIPHER_GLYPHS[] = {
        "0", "1", "A", "C", "E", "F", "7", "9", "░", "▒", "▓", "≡", "≈"
    };
    static const char *const STAR_GLYPHS[] = {"·", "∙", "•", "°"};

    int rows = 48, cols = 170;
    get_term_size(tty_fd, &rows, &cols);
    if (out_rows)
        *out_rows = rows;
    if (out_cols)
        *out_cols = cols;

    clear_canvas(rows, cols);

    uint64_t t_now = now_ms();
    char title[192];
    snprintf(title, sizeof(title), " Enter passphrase for %.127s: ", dev_label);
    int title_len = (int)strlen(title);

    int inner_w = 48;
    if (title_len + 4 > inner_w)
        inner_w = title_len + 4;
    if (inner_w + 2 > cols - 2)
        inner_w = cols - 4;
    if (inner_w < 20)
        inner_w = 20;
    if (title_len > inner_w - 2) {
        title[inner_w - 2] = '\0';
        title_len = inner_w - 2;
    }

    bool full_banner = (cols >= BANNER_WIDTH + 4 && rows >= BANNER_LINES + 8);
    int total_h = full_banner ? (BANNER_LINES + 3 + 3) : (1 + 2 + 3);
    int start_row = (rows - total_h) * 2 / 5;
    if (start_row < 1)
        start_row = 1;
    int banner_col = (cols - BANNER_WIDTH) / 2;
    if (banner_col < 0)
        banner_col = 0;
    int box_row = full_banner ? (start_row + BANNER_LINES + 3) : (start_row + 3);

    /* Horizontal shake on wrong-passphrase retry */
    int shake_dx = 0;
    if (ctx->error_start_ms > 0 && t_now >= ctx->error_start_ms) {
        uint64_t dt_err = t_now - ctx->error_start_ms;
        if (dt_err < 380) {
            static const int SHAKE_SEQ[12] = {-3, 3, -3, 2, -2, 2, -1, 1, -1, 0, 0, 0};
            shake_dx = SHAKE_SEQ[(dt_err * 12) / 380];
        }
    }

    int guard_r0 = start_row - 2;
    int guard_r1 = box_row + 5;
    int guard_c0 = banner_col - 4;
    int guard_c1 = banner_col + BANNER_WIDTH + 4;

    /* Background particle layer (Mode 1: Stardust, Mode 2: Crypto Waterfall) */
    if (full_banner && ctx->mode == 1) {
        for (int i = 0; i < NUM_STARS; i++) {
            ctx->stars[i].col_fp += ctx->stars[i].vx_fp;
            ctx->stars[i].row_fp += ctx->stars[i].vy_fp;
            if (ctx->stars[i].col_fp >= cols * 16)
                ctx->stars[i].col_fp = 0;
            if (ctx->stars[i].row_fp < 0)
                ctx->stars[i].row_fp = (rows - 1) * 16;

            int sr = ctx->stars[i].row_fp / 16;
            int sc = ctx->stars[i].col_fp / 16;
            if (sr >= guard_r0 && sr <= guard_r1 && sc >= guard_c0 && sc <= guard_c1)
                continue;
            enum color_id scol = ((i + ctx->frame / 8) % 5 == 0) ? COL_DEEP_TEAL : COL_DIM_GRAY;
            put_cell(sr, sc, rows, cols, STAR_GLYPHS[ctx->stars[i].kind], scol);
        }
    } else if (full_banner && ctx->mode == 2) {
        for (int c = 1; c < cols - 1; c += 3) {
            ctx->drops[c].row_fp += ctx->drops[c].speed_fp;
            int head_r = ctx->drops[c].row_fp / 16;
            if (head_r - ctx->drops[c].length > rows) {
                ctx->drops[c].row_fp = -(int)(xorshift32(&ctx->rng) % 320);
                ctx->drops[c].speed_fp = 5 + (int)(xorshift32(&ctx->rng) % 9);
            }
            for (int k = 0; k < ctx->drops[c].length; k++) {
                int rr = head_r - k;
                if (rr < 0 || rr >= rows)
                    continue;
                if (rr >= guard_r0 && rr <= guard_r1 && c >= guard_c0 && c <= guard_c1)
                    continue;
                uint32_t h = ctx->drops[c].seed ^ (uint32_t)(rr * 2654435761U) ^ (uint32_t)(ctx->frame / 4);
                const char *g = CIPHER_GLYPHS[h % 10];
                enum color_id dc = (k == 0) ? COL_CYAN_GREEN : (k < 3 ? COL_DEEP_TEAL : COL_DIM_GRAY);
                put_cell(rr, c, rows, cols, g, dc);
            }
        }
    }

    uint64_t dt_intro = ctx->skip_intro ? 99999ULL : (t_now >= ctx->intro_start_ms ? t_now - ctx->intro_start_ms : 0);
    int reveal_col = (dt_intro < 850) ? (int)((dt_intro * (BANNER_WIDTH + 18)) / 850) - 8 : BANNER_WIDTH + 20;

    /* Banner layer */
    if (full_banner) {
        for (int r = 0; r < BANNER_LINES; r++) {
            for (int c = 0; c < BANNER_WIDTH; c++) {
                const struct banner_glyph *bg = &g_banner[r][c];
                if (bg->utf8[0] == ' ')
                    continue;

                int slant_c = c + r * 2;
                if (slant_c > reveal_col + 10)
                    continue;
                if (slant_c > reveal_col) {
                    uint32_t h = (uint32_t)(r * 131 + c * 17 + ctx->frame * 7);
                    const char *cg = CIPHER_GLYPHS[h % 13];
                    enum color_id wc = (slant_c - reveal_col <= 3) ? COL_WHITE : COL_BRIGHT_MINT;
                    put_cell(start_row + r, banner_col + c, rows, cols, cg, wc);
                    continue;
                }

                enum color_id pcol = COL_ACCENT_TEAL;
                if (ctx->mode == 0) {
                    int wave = (c - r * 3 - ctx->frame * 2) % 96;
                    if (wave < 0)
                        wave += 96;
                    if (wave < 4)
                        pcol = COL_WHITE;
                    else if (wave < 11)
                        pcol = COL_BRIGHT_MINT;
                    else if (wave > 52 && wave < 68)
                        pcol = COL_MID_TEAL;
                    else
                        pcol = bg->is_edge ? COL_BRIGHT_MINT : COL_ACCENT_TEAL;
                } else if (ctx->mode == 1) {
                    int v = fast_sin(c / 2 + ctx->frame) + fast_sin(r * 5 - ctx->frame);
                    if (v > 320)
                        pcol = COL_WHITE;
                    else if (v > 120)
                        pcol = COL_BRIGHT_MINT;
                    else if (v > -100)
                        pcol = COL_ACCENT_TEAL;
                    else
                        pcol = COL_MID_TEAL;
                } else if (ctx->mode == 2) {
                    int pulse = fast_sin(ctx->frame - r * 4);
                    if (pulse > 210 && bg->is_edge)
                        pcol = COL_WHITE;
                    else if (pulse > 80)
                        pcol = COL_BRIGHT_MINT;
                    else
                        pcol = COL_ACCENT_TEAL;
                } else {
                    int breath = fast_sin(ctx->frame / 2);
                    pcol = (breath > 160 && bg->is_edge) ? COL_BRIGHT_MINT : COL_ACCENT_TEAL;
                }

                put_cell(start_row + r, banner_col + c, rows, cols, bg->utf8, pcol);
            }
        }
    } else {
        put_ascii_str(start_row, (cols - 10) / 2, rows, cols, "ARCHRELIUS", COL_BRIGHT_MINT);
    }

    /* Mode 4 telemetry horizon bar */
    if (full_banner && ctx->mode == 3 && box_row - 2 > start_row + BANNER_LINES) {
        int hr_row = box_row - 2;
        int bar_half = 34;
        int center_c = cols / 2;
        uint64_t dt_rip = (ctx->ripple_start_ms > 0 && t_now >= ctx->ripple_start_ms)
                              ? (t_now - ctx->ripple_start_ms)
                              : 99999ULL;
        for (int dx = -bar_half; dx <= bar_half; dx++) {
            int dist = dx < 0 ? -dx : dx;
            const char *g = (dist < 10) ? "═" : (dist < 22 ? "─" : "·");
            enum color_id hc = (dist < 10) ? COL_ACCENT_TEAL : COL_DIM_GRAY;
            if (dt_rip < 450) {
                int front = (int)((dt_rip * (uint64_t)bar_half) / 400ULL);
                if (dist >= front - 2 && dist <= front + 2) {
                    g = "▓";
                    hc = COL_BRIGHT_MINT;
                }
            }
            put_cell(hr_row, center_c + dx, rows, cols, g, hc);
        }
    }

    /* Expanding & animated passphrase box */
    int cur_inner_w = inner_w;
    if (!ctx->skip_intro && dt_intro < 450) {
        cur_inner_w = 6 + (int)((dt_intro * (uint64_t)(inner_w - 6)) / 450ULL);
        if (cur_inner_w > inner_w)
            cur_inner_w = inner_w;
    }
    int cur_box_w = cur_inner_w + 2;
    int cur_box_col = (cols - cur_box_w) / 2 + shake_dx;

    enum color_id border_base =
        (ctx->error_start_ms > 0 && t_now >= ctx->error_start_ms && (t_now - ctx->error_start_ms) < 600)
            ? COL_RED
            : COL_SOFT_WHITE;

    int perim = 2 * cur_box_w + 2;
    int comet1 = (ctx->frame * 2) % perim;
    int comet2 = (comet1 + perim / 2) % perim;

    int rip_radius = -1;
    if (ctx->ripple_start_ms > 0 && t_now >= ctx->ripple_start_ms && (t_now - ctx->ripple_start_ms) < 360) {
        rip_radius = (int)(((t_now - ctx->ripple_start_ms) * (uint64_t)(cur_inner_w / 2 + 4)) / 360ULL);
    }

    put_cell(box_row, cur_box_col, rows, cols, "┌", COL_WHITE);
    for (int i = 0; i < cur_inner_w; i++) {
        int dist_center = i - cur_inner_w / 2;
        if (dist_center < 0)
            dist_center = -dist_center;

        enum color_id cc = border_base;
        int p_idx = i + 1;
        if (p_idx == comet1 || p_idx == comet2)
            cc = COL_BRIGHT_MINT;
        if (rip_radius >= 0 && dist_center >= rip_radius - 2 && dist_center <= rip_radius + 2)
            cc = COL_BRIGHT_MINT;

        if (cur_inner_w == inner_w && i >= 1 && i - 1 < title_len) {
            char ch_s[2] = {title[i - 1], '\0'};
            enum color_id tc = (rip_radius >= 0 && dist_center <= rip_radius + 1) ? COL_BRIGHT_MINT : COL_WHITE;
            if (border_base == COL_RED)
                tc = COL_RED;
            put_cell(box_row, cur_box_col + 1 + i, rows, cols, ch_s, tc);
        } else {
            put_cell(box_row, cur_box_col + 1 + i, rows, cols, "─", cc);
        }
    }
    put_cell(box_row, cur_box_col + cur_inner_w + 1, rows, cols, "┐", COL_WHITE);

    enum color_id side_c = (rip_radius >= cur_inner_w / 2 - 1) ? COL_BRIGHT_MINT : border_base;
    put_cell(box_row + 1, cur_box_col, rows, cols, "│", side_c);

    if (unlocking_bar) {
        int cycle = (int)((unlock_elapsed_ms * (uint64_t)(cur_inner_w * 2)) / 1400ULL) % (cur_inner_w * 2);
        int pos = (cycle < cur_inner_w) ? cycle : (cur_inner_w * 2 - 1 - cycle);
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
        const char *cur_glyph = ((ctx->frame / 10) % 2 == 0) ? "█" : "▓";
        enum color_id cur_col = (rip_radius >= 0) ? COL_BRIGHT_MINT : COL_ACCENT_TEAL;
        put_cell(box_row + 1, cur_box_col + 2, rows, cols, cur_glyph, cur_col);
    }

    put_cell(box_row + 1, cur_box_col + cur_inner_w + 1, rows, cols, "│", side_c);

    put_cell(box_row + 2, cur_box_col, rows, cols, "└", COL_WHITE);
    for (int i = 0; i < cur_inner_w; i++) {
        int dist_center = i - cur_inner_w / 2;
        if (dist_center < 0)
            dist_center = -dist_center;

        enum color_id cc = border_base;
        int p_idx = cur_box_w + 1 + (cur_inner_w - 1 - i);
        if (p_idx == comet1 || p_idx == comet2)
            cc = COL_BRIGHT_MINT;
        if (rip_radius >= 0 && dist_center >= rip_radius - 2 && dist_center <= rip_radius + 2)
            cc = COL_BRIGHT_MINT;
        put_cell(box_row + 2, cur_box_col + 1 + i, rows, cols, "─", cc);
    }
    put_cell(box_row + 2, cur_box_col + cur_inner_w + 1, rows, cols, "┘", COL_WHITE);

    /* Status / transient theme switch indicator below box */
    if (box_row + 4 < rows) {
        if (unlocking_bar) {
            const char *umsg = "Unlocking volume (argon2id)...";
            put_ascii_str(box_row + 4, (cols - (int)strlen(umsg)) / 2, rows, cols, umsg, COL_ACCENT_TEAL);
        } else if (show_err) {
            const char *emsg = "Incorrect passphrase, try again.";
            put_ascii_str(box_row + 4, (cols - (int)strlen(emsg)) / 2 + shake_dx, rows, cols, emsg, COL_RED);
        } else if (ctx->mode_toast_ms > 0 && t_now >= ctx->mode_toast_ms && (t_now - ctx->mode_toast_ms) < 1300) {
            const char *tmsg = MODE_LABELS[ctx->mode & 3];
            put_ascii_str(box_row + 4, (cols - (int)strlen(tmsg)) / 2, rows, cols, tmsg, COL_DIM_GRAY);
        }
    }

    /* Single-buffer flush with trailing-space trim (\033[K) for flicker-free low-IO output */
    size_t pos = 0;
    pos += (size_t)snprintf(g_outbuf + pos, sizeof(g_outbuf) - pos, "\033[?25l\033[H\033[0m");
    enum color_id cur_color = COL_DEFAULT;

    for (int r = 0; r < rows; r++) {
        if (r > 0)
            pos += (size_t)snprintf(g_outbuf + pos, sizeof(g_outbuf) - pos, "\r\n");

        int last_non_space = -1;
        for (int c = cols - 1; c >= 0; c--) {
            if (!(g_canvas[r][c].utf8[0] == ' ' && g_canvas[r][c].utf8[1] == '\0')) {
                last_non_space = c;
                break;
            }
        }
        for (int c = 0; c <= last_non_space; c++) {
            const struct cell *cl = &g_canvas[r][c];
            if (cl->color != cur_color) {
                const char *cs = color_seq(cl->color, ctx->is_linux_vt);
                size_t cslen = strlen(cs);
                if (pos + cslen + 16 < sizeof(g_outbuf)) {
                    memcpy(g_outbuf + pos, cs, cslen);
                    pos += cslen;
                }
                cur_color = cl->color;
            }
            size_t glen = strlen(cl->utf8);
            if (pos + glen + 16 < sizeof(g_outbuf)) {
                memcpy(g_outbuf + pos, cl->utf8, glen);
                pos += glen;
            }
        }
        if (cur_color != COL_DEFAULT) {
            memcpy(g_outbuf + pos, "\033[0m", 4);
            pos += 4;
            cur_color = COL_DEFAULT;
        }
        if (last_non_space < cols - 1 && pos + 8 < sizeof(g_outbuf)) {
            memcpy(g_outbuf + pos, "\033[K", 3);
            pos += 3;
        }
    }

    (void)write_all(tty_fd, g_outbuf, pos);
    ctx->frame++;
}

static void clear_tty(int tty_fd, bool is_linux_vt) {
    if (is_linux_vt)
        write_str(tty_fd, "\033]R\033[0m\033[?25h\033[2J\033[H");
    else
        write_str(tty_fd, "\033[0m\033[?25h\033[2J\033[H");
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

static int send_passphrase_reply(const char *socket_path, const char *pass, size_t pass_len) {
    if (!is_trusted_socket(socket_path))
        return -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    size_t slen = strlen(socket_path);
    if (slen == 0 || slen >= sizeof(sa.sun_path))
        return -1;
    memcpy(sa.sun_path, socket_path, slen);
    socklen_t addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + slen + 1);

    char pkt[MAX_PASS_LEN + 2];
    (void)mlock(pkt, sizeof(pkt));
    pkt[0] = '+';
    if (pass_len > 0)
        memcpy(pkt + 1, pass, pass_len);

    int sfd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int rc = -1;
    if (sfd >= 0) {
        ssize_t sent = sendto(sfd, pkt, pass_len + 1, MSG_NOSIGNAL,
                              (const struct sockaddr *)&sa, addrlen);
        if (sent == (ssize_t)(pass_len + 1))
            rc = 0;
        close(sfd);
    }

    explicit_bzero(pkt, sizeof(pkt));
    (void)munlock(pkt, sizeof(pkt));
    return rc;
}

enum prompt_result {
    PROMPT_SUBMITTED = 0,
    PROMPT_VANISHED  = 1,
    PROMPT_STOPPED   = 2,
};

static enum prompt_result prompt_user_on_tty(
    int tty_fd,
    int inotify_fd,
    struct anim_ctx *ctx,
    const struct ask_request *req,
    bool show_retry_err
) {
    struct termios old_tio, raw_tio;
    bool have_tio = (tcgetattr(tty_fd, &old_tio) == 0);
    if (have_tio) {
        raw_tio = old_tio;
        raw_tio.c_lflag &= (tcflag_t) ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON | ISIG | IEXTEN);
        raw_tio.c_iflag &= (tcflag_t) ~(IXON | ICRNL);
        raw_tio.c_cc[VMIN] = 1;
        raw_tio.c_cc[VTIME] = 0;
        (void)tcsetattr(tty_fd, TCSANOW, &raw_tio);
        (void)tcflush(tty_fd, TCIFLUSH);
    }

    apply_vt_palette(tty_fd, ctx->is_linux_vt);

    char pass[MAX_PASS_LEN + 1];
    memset(pass, 0, sizeof(pass));
    (void)mlock(pass, sizeof(pass));
    size_t pass_len = 0;

    bool err_visible = show_retry_err;
    if (show_retry_err) {
        ctx->error_start_ms = now_ms();
        ctx->last_input_ms = ctx->error_start_ms;
    }

    int drawn_rows = 0, drawn_cols = 0;
    int settle_ticks = 0;

    render_frame(tty_fd, ctx, req->dev_label, err_visible, false, 0, &drawn_rows, &drawn_cols);

    enum prompt_result res = PROMPT_STOPPED;

    while (!g_stop) {
        int cur_rows = 0, cur_cols = 0;
        get_term_size(tty_fd, &cur_rows, &cur_cols);

        if (g_winch || cur_rows != drawn_rows || cur_cols != drawn_cols) {
            g_winch = 0;
            if (have_tio)
                (void)tcsetattr(tty_fd, TCSANOW, &raw_tio);
            apply_vt_palette(tty_fd, ctx->is_linux_vt);
            write_str(tty_fd, "\033[2J\033[H");
            ctx->last_input_ms = now_ms();
            settle_ticks = 6;
        } else if (settle_ticks > 0) {
            settle_ticks--;
            if (settle_ticks == 0) {
                if (have_tio)
                    (void)tcsetattr(tty_fd, TCSANOW, &raw_tio);
                apply_vt_palette(tty_fd, ctx->is_linux_vt);
            }
        }

        if (access(req->ask_path, F_OK) != 0) {
            res = PROMPT_VANISHED;
            break;
        }

        uint64_t t_now = now_ms();
        int timeout_ms = (t_now >= ctx->last_input_ms && (t_now - ctx->last_input_ms) > IDLE_AFTER_MS)
                             ? IDLE_FRAME_MS
                             : ACTIVE_FRAME_MS;

        struct pollfd pfds[2] = {
            {.fd = tty_fd, .events = POLLIN},
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
            if (access(req->ask_path, F_OK) != 0) {
                res = PROMPT_VANISHED;
                break;
            }
        }

        if (prc > 0 && (pfds[0].revents & POLLIN)) {
            struct pollfd kpfd = {.fd = tty_fd, .events = POLLIN};
            bool submitted_now = false;
            while (poll(&kpfd, 1, 0) > 0 && (kpfd.revents & POLLIN)) {
                char ch = 0;
                ssize_t n = read(tty_fd, &ch, 1);
                if (n <= 0)
                    break;

                unsigned char uch = (unsigned char)ch;
                ctx->last_input_ms = now_ms();

                if (uch == '\r' || uch == '\n') {
                    render_frame(tty_fd, ctx, req->dev_label, false, true, 0,
                                 &drawn_rows, &drawn_cols);
                    (void)send_passphrase_reply(req->socket_path, pass, pass_len);
                    res = PROMPT_SUBMITTED;
                    submitted_now = true;
                    break;
                } else if (uch == '\t') {
                    /* Tab switches animation theme live without clearing typed buffer */
                    ctx->mode = (ctx->mode + 1) % 4;
                    ctx->mode_toast_ms = ctx->last_input_ms;
                } else if (uch == 0x7f || uch == 0x08) {
                    pass_len = pop_last_utf8_char(pass, pass_len);
                    ctx->ripple_start_ms = ctx->last_input_ms;
                } else if (uch == 0x15) {
                    explicit_bzero(pass, sizeof(pass));
                    pass_len = 0;
                    ctx->ripple_start_ms = ctx->last_input_ms;
                } else if (uch == 0x1b) {
                    drain_escape_sequence(tty_fd);
                } else if (uch >= 0x20) {
                    err_visible = false;
                    ctx->error_start_ms = 0;
                    ctx->ripple_start_ms = ctx->last_input_ms;
                    if (pass_len < MAX_PASS_LEN) {
                        pass[pass_len++] = ch;
                        pass[pass_len] = '\0';
                    }
                }
            }
            if (submitted_now)
                break;
        }

        render_frame(tty_fd, ctx, req->dev_label, err_visible, false, 0, &drawn_rows, &drawn_cols);
    }

    explicit_bzero(pass, sizeof(pass));
    (void)munlock(pass, sizeof(pass));
    if (have_tio)
        (void)tcsetattr(tty_fd, TCSANOW, &old_tio);
    return res;
}

static void fallback_to_stock_agent(bool watch_mode) {
    if (access(FALLBACK_AGENT, X_OK) == 0) {
        execl(FALLBACK_AGENT, "systemd-tty-ask-password-agent",
              watch_mode ? "--watch" : "--query", "--console", (char *)NULL);
    }
}

int main(int argc, char *argv[]) {
    bool watch_mode = false;
    bool custom_env = false;
    bool skip_intro = false;
    const char *ask_dir = DEFAULT_ASK_DIR;
    const char *explicit_tty = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--watch") == 0) {
            watch_mode = true;
        } else if (strcmp(argv[i], "--query") == 0) {
            watch_mode = false;
        } else if (strcmp(argv[i], "--no-intro") == 0) {
            skip_intro = true;
        } else if (strcmp(argv[i], "--console") == 0) {
            /* Default behavior */
        } else if (strncmp(argv[i], "--console=", 10) == 0) {
            explicit_tty = argv[i] + 10;
        } else if (strncmp(argv[i], "--tty=", 6) == 0) {
            explicit_tty = argv[i] + 6;
            custom_env = true;
        } else if (strncmp(argv[i], "--ask-dir=", 10) == 0) {
            ask_dir = argv[i] + 10;
            custom_env = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [--watch|--query] [--console[=DEV]] [--tty=DEV] [--ask-dir=DIR]\n", argv[0]);
            return 0;
        }
    }

    decode_banner_once();

    struct sigaction sa_stop, sa_winch, sa_ign;
    memset(&sa_stop, 0, sizeof(sa_stop));
    sa_stop.sa_handler = on_stop_signal;
    sigemptyset(&sa_stop.sa_mask);
    (void)sigaction(SIGTERM, &sa_stop, NULL);
    (void)sigaction(SIGINT, &sa_stop, NULL);
    (void)sigaction(SIGHUP, &sa_stop, NULL);

    memset(&sa_winch, 0, sizeof(sa_winch));
    sa_winch.sa_handler = on_winch_signal;
    sigemptyset(&sa_winch.sa_mask);
    (void)sigaction(SIGWINCH, &sa_winch, NULL);

    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &sa_ign, NULL);

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
    init_anim_ctx(&ctx, tty_fd, skip_intro);

    sd_notify_ready();

    char last_id[256] = {0};
    char last_ask_path[PATH_MAX] = {0};
    char last_dev_label[128] = "/dev/mapper/root";
    uint64_t submit_ms = 0;
    int attempts_for_id = 0;
    bool drew_anything = false;

    while (!g_stop) {
        struct ask_request req;
        if (find_pending_request(ask_dir, &req)) {
            /* Animate bidirectional Argon2id scanner while systemd-cryptsetup verifies key */
            if (strcmp(req.ask_path, last_ask_path) == 0) {
                uint64_t elapsed = (submit_ms > 0 && now_ms() >= submit_ms) ? (now_ms() - submit_ms) : 0;
                render_frame(tty_fd, &ctx, last_dev_label, false, true, elapsed, NULL, NULL);
                struct pollfd pfd = {.fd = inotify_fd, .events = POLLIN};
                (void)poll(&pfd, 1, ACTIVE_FRAME_MS);
                if (pfd.revents & POLLIN)
                    drain_inotify(inotify_fd);
                continue;
            }

            if (req.id[0] != '\0' && strcmp(req.id, last_id) == 0) {
                attempts_for_id++;
                ctx.skip_intro = true;
            } else {
                snprintf(last_id, sizeof(last_id), "%s", req.id);
                attempts_for_id = 0;
            }
            snprintf(last_dev_label, sizeof(last_dev_label), "%s", req.dev_label);

            if (!drew_anything)
                write_str(tty_fd, "\033[2J\033[H");
            drew_anything = true;

            enum prompt_result pr = prompt_user_on_tty(
                tty_fd, inotify_fd, &ctx, &req, attempts_for_id > 0);
            if (pr == PROMPT_SUBMITTED) {
                snprintf(last_ask_path, sizeof(last_ask_path), "%s", req.ask_path);
                submit_ms = now_ms();
            }
            if (!watch_mode)
                break;
            continue;
        }

        if (!watch_mode)
            break;

        struct pollfd pfd = {.fd = inotify_fd, .events = POLLIN};
        int prc = poll(&pfd, 1, 250);
        if (prc > 0 && (pfd.revents & POLLIN))
            drain_inotify(inotify_fd);
    }

    if (drew_anything)
        clear_tty(tty_fd, ctx.is_linux_vt);

    close(tty_fd);
    close(inotify_fd);
    return 0;
}
