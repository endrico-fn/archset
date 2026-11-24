/* SPDX-License-Identifier: MIT
 *
 * archrelius-askpw.c — Minimal, memory-safe systemd Password Agent TUI
 * Implements https://systemd.io/PASSWORD_AGENTS/ for initramfs LUKS2 unlock.
 *
 * Security & reliability properties:
 * - Pure glibc (zero external shared library dependencies beyond libc.so.6).
 * - Passphrase buffer locked in RAM via mlock() and wiped via explicit_bzero().
 * - Atomic ask.* parsing, monotonic NotAfter check, and live PID verification.
 * - Multi-byte ANSI/VT escape sequence draining (arrow/fn keys never corrupt input).
 * - Automatic execv fallback to /usr/bin/systemd-tty-ask-password-agent on error.
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
#define BANNER_LINES    9
#define BANNER_WIDTH    116

static const char *const BANNER[BANNER_LINES] = {
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

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_winch = 0;

struct ask_request {
    char ask_path[PATH_MAX];
    char socket_path[PATH_MAX];
    char id[256];
    char message[256];
    char dev_label[128];
    pid_t pid;
    uint64_t not_after_usec;
};

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

static uint64_t now_monotonic_usec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
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

    /* /sys/class/tty/console/active lists space-separated consoles; last is primary */
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
    if (explicit_tty && *explicit_tty) {
        return open(explicit_tty, O_RDWR | O_NOCTTY | O_CLOEXEC);
    }

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
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
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
        /* systemd creates hidden temp files before atomic rename to ask.XXXX */
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
        *rows = (int)ws.ws_row;
        *cols = (int)ws.ws_col;
    } else {
        *rows = 48;
        *cols = 170;
    }
}

static void goto_rc(int fd, int row, int col) {
    char seq[32];
    if (row < 1)
        row = 1;
    if (col < 1)
        col = 1;
    int n = snprintf(seq, sizeof(seq), "\033[%d;%dH", row, col);
    if (n > 0)
        (void)write_all(fd, seq, (size_t)n);
}

static void write_repeat(int fd, const char *glyph, int count) {
    size_t glen = strlen(glyph);
    for (int i = 0; i < count; i++)
        (void)write_all(fd, glyph, glen);
}

static void render_tui(
    int tty_fd,
    const char *dev_label,
    const char *status_msg,
    bool status_is_err,
    int *out_rows,
    int *out_cols
) {
    int rows = 48, cols = 170;
    get_term_size(tty_fd, &rows, &cols);
    if (out_rows)
        *out_rows = rows;
    if (out_cols)
        *out_cols = cols;

    char title[192];
    snprintf(title, sizeof(title), " Enter passphrase for %.127s: ", dev_label);
    int title_len = (int)strlen(title);

    /* Exact 50-col box (48 inner chars) with symmetric 1-space label padding */
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
    int box_w = inner_w + 2;

    bool full_banner = (cols >= BANNER_WIDTH + 4 && rows >= BANNER_LINES + 8);
    int total_h = full_banner ? (BANNER_LINES + 3 + 3) : (1 + 2 + 3);
    int start_row = (rows - total_h) * 2 / 5 + 1;
    if (start_row < 2)
        start_row = 2;

    /* Reset attributes, clear screen, hide cursor while drawing */
    write_str(tty_fd, "\033[0m\033[?25l\033[2J\033[H");

    int box_row = start_row;
    if (full_banner) {
        int banner_col = (cols - BANNER_WIDTH) / 2 + 1;
        /* Arch Linux Blue (#1793d1 truecolor; maps cleanly to bold cyan on Linux VT) */
        write_str(tty_fd, "\033[1;36m\033[38;2;23;147;209m");
        for (int i = 0; i < BANNER_LINES; i++) {
            goto_rc(tty_fd, start_row + i, banner_col);
            write_str(tty_fd, BANNER[i]);
        }
        box_row = start_row + BANNER_LINES + 3;
    } else {
        const char *compact = "ARCHRELIUS";
        int ccol = (cols - (int)strlen(compact)) / 2 + 1;
        write_str(tty_fd, "\033[1;36m");
        goto_rc(tty_fd, start_row, ccol);
        write_str(tty_fd, compact);
        box_row = start_row + 3;
    }

    int box_col = (cols - box_w) / 2 + 1;
    int right_dashes = inner_w - 1 - title_len;
    if (right_dashes < 0)
        right_dashes = 0;

    /* Box in bold white */
    write_str(tty_fd, "\033[0m\033[1;37m");

    /* Top border: ┌─ Enter passphrase for /dev/nvme0n1p2: ─────────┐ */
    goto_rc(tty_fd, box_row, box_col);
    write_str(tty_fd, "┌─");
    write_str(tty_fd, title);
    write_repeat(tty_fd, "─", right_dashes);
    write_str(tty_fd, "┐");

    /* Middle input row: │                                                │ */
    goto_rc(tty_fd, box_row + 1, box_col);
    write_str(tty_fd, "│");
    write_repeat(tty_fd, " ", inner_w);
    write_str(tty_fd, "│");

    /* Bottom border: └────────────────────────────────────────────────┘ */
    goto_rc(tty_fd, box_row + 2, box_col);
    write_str(tty_fd, "└");
    write_repeat(tty_fd, "─", inner_w);
    write_str(tty_fd, "┘");

    if (status_msg && *status_msg && box_row + 4 <= rows) {
        int scol = (cols - (int)strlen(status_msg)) / 2 + 1;
        goto_rc(tty_fd, box_row + 4, scol);
        write_str(tty_fd, status_is_err ? "\033[1;31m" : "\033[0;90m");
        write_str(tty_fd, status_msg);
    }

    /* Place visible cursor inside the box (no echo on input) */
    write_str(tty_fd, "\033[0m\033[?25h");
    goto_rc(tty_fd, box_row + 1, box_col + 2);
}

static void clear_tty(int tty_fd) {
    write_str(tty_fd, "\033[0m\033[?25h\033[2J\033[H");
}

static void drain_escape_sequence(int tty_fd) {
    struct pollfd pfd = {.fd = tty_fd, .events = POLLIN};
    char ch = 0;
    /* Drain bytes belonging to CSI (\033[...) or SS3 (\033O...) sequences */
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
        /* Drain queued events */
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

    char pass[MAX_PASS_LEN + 1];
    memset(pass, 0, sizeof(pass));
    (void)mlock(pass, sizeof(pass));
    size_t pass_len = 0;

    bool err_visible = show_retry_err;
    int drawn_rows = 0, drawn_cols = 0;
    int settle_ticks = 0;

    render_tui(tty_fd, req->dev_label,
               err_visible ? "Incorrect passphrase, try again." : NULL, true,
               &drawn_rows, &drawn_cols);

    enum prompt_result res = PROMPT_STOPPED;

    while (!g_stop) {
        int cur_rows = 0, cur_cols = 0;
        get_term_size(tty_fd, &cur_rows, &cur_cols);

        /* Detect KMS deferred fbcon takeover (e.g. 160x50 -> 170x48 on i915drmfb)
         * even without SIGWINCH (O_NOCTTY), plus one settled redraw ~300ms later
         * after systemd-vconsole-setup loads default8x16 Unicode map. */
        if (g_winch || cur_rows != drawn_rows || cur_cols != drawn_cols) {
            g_winch = 0;
            if (have_tio)
                (void)tcsetattr(tty_fd, TCSANOW, &raw_tio);
            render_tui(tty_fd, req->dev_label,
                       err_visible ? "Incorrect passphrase, try again." : NULL, true,
                       &drawn_rows, &drawn_cols);
            settle_ticks = 2;
        } else if (settle_ticks > 0) {
            settle_ticks--;
            if (settle_ticks == 0) {
                if (have_tio)
                    (void)tcsetattr(tty_fd, TCSANOW, &raw_tio);
                render_tui(tty_fd, req->dev_label,
                           err_visible ? "Incorrect passphrase, try again." : NULL, true,
                           &drawn_rows, &drawn_cols);
            }
        }

        if (access(req->ask_path, F_OK) != 0) {
            res = PROMPT_VANISHED;
            break;
        }

        struct pollfd pfds[2] = {
            {.fd = tty_fd, .events = POLLIN},
            {.fd = inotify_fd, .events = POLLIN},
        };
        int prc = poll(pfds, 2, 150);
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (prc == 0)
            continue;

        if (pfds[1].revents & POLLIN) {
            drain_inotify(inotify_fd);
            if (access(req->ask_path, F_OK) != 0) {
                res = PROMPT_VANISHED;
                break;
            }
        }

        if (pfds[0].revents & POLLIN) {
            char ch = 0;
            ssize_t n = read(tty_fd, &ch, 1);
            if (n <= 0)
                continue;

            unsigned char uch = (unsigned char)ch;
            if (uch == '\r' || uch == '\n') {
                render_tui(tty_fd, req->dev_label, "Unlocking...", false,
                           &drawn_rows, &drawn_cols);
                (void)send_passphrase_reply(req->socket_path, pass, pass_len);
                res = PROMPT_SUBMITTED;
                break;
            } else if (uch == 0x7f || uch == 0x08) {
                pass_len = pop_last_utf8_char(pass, pass_len);
            } else if (uch == 0x15) {
                /* Ctrl+U clears typed buffer */
                explicit_bzero(pass, sizeof(pass));
                pass_len = 0;
            } else if (uch == 0x1b) {
                /* Drain arrow / navigation / function key escape sequences */
                drain_escape_sequence(tty_fd);
            } else if (uch >= 0x20) {
                if (err_visible) {
                    err_visible = false;
                    render_tui(tty_fd, req->dev_label, NULL, false,
                               &drawn_rows, &drawn_cols);
                }
                if (pass_len < MAX_PASS_LEN) {
                    pass[pass_len++] = ch;
                    pass[pass_len] = '\0';
                }
            }
        }
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
    const char *ask_dir = DEFAULT_ASK_DIR;
    const char *explicit_tty = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--watch") == 0) {
            watch_mode = true;
        } else if (strcmp(argv[i], "--query") == 0) {
            watch_mode = false;
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

    sd_notify_ready();

    char last_id[256] = {0};
    char last_ask_path[PATH_MAX] = {0};
    int attempts_for_id = 0;
    bool drew_anything = false;

    while (!g_stop) {
        struct ask_request req;
        if (find_pending_request(ask_dir, &req)) {
            /* Avoid re-querying the exact same ask.* file right after sending reply
             * while systemd-cryptsetup is still running Argon2id before unlinking it. */
            if (strcmp(req.ask_path, last_ask_path) == 0) {
                struct pollfd pfd = {.fd = inotify_fd, .events = POLLIN};
                (void)poll(&pfd, 1, 50);
                if (pfd.revents & POLLIN)
                    drain_inotify(inotify_fd);
                continue;
            }

            if (req.id[0] != '\0' && strcmp(req.id, last_id) == 0) {
                attempts_for_id++;
            } else {
                snprintf(last_id, sizeof(last_id), "%s", req.id);
                attempts_for_id = 0;
            }

            drew_anything = true;
            enum prompt_result pr = prompt_user_on_tty(
                tty_fd, inotify_fd, &req, attempts_for_id > 0);
            if (pr == PROMPT_SUBMITTED) {
                snprintf(last_ask_path, sizeof(last_ask_path), "%s", req.ask_path);
            }
            if (!watch_mode)
                break;
            continue;
        }

        if (!watch_mode)
            break;

        struct pollfd pfd = {.fd = inotify_fd, .events = POLLIN};
        int prc = poll(&pfd, 1, 500);
        if (prc > 0 && (pfd.revents & POLLIN))
            drain_inotify(inotify_fd);
    }

    if (drew_anything)
        clear_tty(tty_fd);

    close(tty_fd);
    close(inotify_fd);
    return 0;
}
