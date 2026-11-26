#!/usr/bin/env python3
"""Terminal UI, secret-safe raw logging, single-instance lock, and subprocess helpers."""

from __future__ import annotations

import fcntl
import getpass
import os
import selectors
import shlex
import shutil
import subprocess
import sys
import textwrap
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

LOG_DIR = "/var/log/archset"
DEFAULT_LOCK_PATH = "/run/archset.lock"
VERSION = "2.0.0"

# Global switches, set by archset.py before any installer step runs.
DRY_RUN = False

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN = "\033[36m"


class ArchsetError(RuntimeError):
    """Fatal, user-facing installer error."""


class CommandError(ArchsetError):
    """A subprocess exited with a non-zero status."""

    def __init__(self, command: str, returncode: int, output: str) -> None:
        self.command = command
        self.returncode = returncode
        self.output = output
        message = f"Command failed with exit code {returncode}: {command}"
        if output:
            message += f"\n{output}"
        super().__init__(message)


@dataclass
class Result:
    command: str
    returncode: int
    stdout: str
    stderr: str


def _paint(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


class InstanceLock:
    """Exclusive non-blocking lock preventing accidental double execution."""

    def __init__(self, path: str | Path = DEFAULT_LOCK_PATH) -> None:
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise ArchsetError(
                f"Another archset instance is already running (lock held: {self.path})."
            ) from exc
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> InstanceLock:
        self.acquire()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.release()


class _Logger:
    def __init__(self) -> None:
        self.path: Path | None = None
        self._fh = None
        self._secrets: list[str] = []

    def init(self, log_dir: str = LOG_DIR) -> Path:
        directory = Path(log_dir)
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = directory / f"archset-{stamp}.log"
        self._fh = self.path.open("w", encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        self._write("INFO", f"archset {VERSION} log started (pid={os.getpid()})")
        return self.path

    def register_secret(self, secret: str) -> None:
        if secret and len(secret) >= 4 and secret not in self._secrets:
            self._secrets.append(secret)

    def clear_secrets(self) -> None:
        self._secrets.clear()

    def redact(self, text: str) -> str:
        result = str(text)
        for secret in self._secrets:
            result = result.replace(secret, "***REDACTED***")
        return result

    def _write(self, level: str, message: str) -> None:
        if self._fh is None:
            return
        clean = self.redact(message)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for line in clean.splitlines() or [""]:
            self._fh.write(f"[{stamp}] {level:<8} {line}\n")
        self._fh.flush()

    def debug(self, message: str) -> None:
        self._write("DEBUG", message)

    def info(self, message: str) -> None:
        self._write("INFO", message)
        print(f"{_paint('[*]', _CYAN)} {self.redact(message)}", flush=True)

    def ok(self, message: str) -> None:
        self._write("OK", message)
        print(f"{_paint('[+]', _GREEN)} {self.redact(message)}", flush=True)

    def warn(self, message: str) -> None:
        self._write("WARN", message)
        print(f"{_paint('[!]', _YELLOW)} {self.redact(message)}", flush=True)

    def error(self, message: str) -> None:
        self._write("ERROR", message)
        print(f"{_paint('[x]', _RED)} {self.redact(message)}", flush=True)

    def step(self, number: int, total: int, title: str) -> None:
        self._write("STEP", f"step {number}/{total}: {title}")
        print(flush=True)
        print(
            f"{_paint(f'==> [{number}/{total}]', _BOLD + _BLUE)} "
            f"{_paint(title, _BOLD)}",
            flush=True,
        )

    def close(self) -> None:
        if self._fh is not None:
            self._write("INFO", "Log closed")
            self._fh.close()
            self._fh = None


log = _Logger()


def init(log_dir: str = LOG_DIR) -> Path:
    return log.init(log_dir)


def debug(message: str) -> None:
    log.debug(message)


def info(message: str) -> None:
    log.info(message)


def ok(message: str) -> None:
    log.ok(message)


def warn(message: str) -> None:
    log.warn(message)


def error(message: str) -> None:
    log.error(message)


def step(number: int, total: int, title: str) -> None:
    log.step(number, total, title)


def banner() -> None:
    lines = [
        "    _              _          _   ",
        "   / \\   _ __ ___| |__  ___ | |_ ",
        "  / _ \\ | '__/ __| '_ \\/ __|| __|",
        " / ___ \\| | | (__| | | \\__ \\| |_ ",
        "/_/   \\_\\_|  \\___|_| |_|___/ \\__|",
    ]
    print(_paint("\n".join(lines), _BOLD + _CYAN))
    print(f"  opinionated Arch Linux installer  v{VERSION}\n")


def hr(char: str = "-", width: int = 72) -> None:
    print(_paint(char * width, _DIM))


def render_package_table(title: str, groups: dict[str, list[str]]) -> None:
    """Render an Arch-ISO TTY-friendly (<= 76 col) grouped package list."""
    print()
    hr("=", 76)
    print(_paint(f"  {title}", _BOLD + _CYAN))
    hr("-", 76)
    total = 0
    for idx, (label, packages) in enumerate(groups.items(), start=1):
        total += len(packages)
        header = f"    [ {idx} ] {label} ({len(packages)} pkgs)"
        print(_paint(header, _BOLD))
        wrapped = textwrap.fill(
            ", ".join(packages),
            width=74,
            initial_indent="          ",
            subsequent_indent="          ",
            break_on_hyphens=False,
        )
        print(wrapped)
    hr("-", 76)
    print(
        f"    [ a ] Install ALL groups    * [ n ] Skip / None   "
        f"({total} pkgs across {len(groups)} groups)"
    )
    hr("=", 76)


def render_download_plan(rows: list[dict[str, object]]) -> tuple[int, float, float]:
    """Render an Arch-TTY-safe (<= 78 col) package download & installed size table.

    Returns ``(new_count, total_download_mib, total_installed_mib)``.
    """
    print()
    hr("=", 76)
    print(_paint("  Download & Installation Plan", _BOLD + _CYAN))
    hr("-", 76)
    header = f"  {'Package':<22} {'Repo':<9} {'Version':<17} {'Download':>10}  {'Status':<10}"
    print(_paint(header, _BOLD))
    hr("-", 76)

    new_count = 0
    total_dl = 0.0
    total_inst = 0.0

    for row in rows:
        name = str(row.get("name", ""))[:22]
        repo = str(row.get("repo", "-"))[:9]
        version = str(row.get("version", "-"))[:17]
        dl_mib = row.get("download_mib")
        inst_mib = row.get("installed_mib")
        installed = bool(row.get("installed", False))

        if isinstance(dl_mib, (int, float)):
            dl_str = f"{dl_mib:6.1f} MiB"
            if not installed:
                total_dl += float(dl_mib)
        else:
            dl_str = "       n/a"

        if isinstance(inst_mib, (int, float)) and not installed:
            total_inst += float(inst_mib)

        if installed:
            status_raw = "installed"
            status_str = _paint(f"{status_raw:<10}", _DIM)
        else:
            new_count += 1
            status_raw = "download"
            status_str = _paint(f"{status_raw:<10}", _GREEN)

        print(f"  {name:<22} {repo:<9} {version:<17} {dl_str:>10}  {status_str}")

    hr("-", 76)
    installed_count = len(rows) - new_count
    print(
        f"  Packages : {len(rows)} selected ({new_count} to download, "
        f"{installed_count} already installed)"
    )
    print(
        f"  Est. Size: ~{total_dl:.1f} MiB download  |  ~{total_inst:.1f} MiB net disk usage"
    )
    hr("=", 76)
    return new_count, total_dl, total_inst


def _run_streaming_pipes(
    argv: list[str],
    display: str,
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    timeout: int | None,
    stream_label: str | None,
) -> tuple[int, str, str]:
    started = time.monotonic()
    deadline = (started + timeout) if timeout is not None else None
    show_live = bool(stream_label and sys.stdout.isatty())
    last_draw = 0.0

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
    except FileNotFoundError as exc:
        raise CommandError(display, 127, f"executable not found: {argv[0]}") from exc

    assert proc.stdout is not None and proc.stderr is not None
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, "STDOUT")
    sel.register(proc.stderr, selectors.EVENT_READ, "STDERR")

    buffers: dict[str, bytearray] = {"STDOUT": bytearray(), "STDERR": bytearray()}
    collected: dict[str, list[str]] = {"STDOUT": [], "STDERR": []}

    def _emit_line(tag: str, raw_bytes: bytes) -> None:
        nonlocal last_draw
        line = raw_bytes.decode("utf-8", errors="replace").rstrip("\r")
        collected[tag].append(line)
        log.debug(f"{tag:<6} | {line[:2000]}")
        if show_live and line.strip():
            now_t = time.monotonic()
            if now_t - last_draw >= 0.12:
                last_draw = now_t
                elapsed_s = int(now_t - started)
                clean_snip = log.redact(line.strip())[:40]
                status = (
                    f"\r\033[K{_paint('[*]', _CYAN)} {stream_label} "
                    f"[{elapsed_s // 60:02d}:{elapsed_s % 60:02d}] {clean_snip}"
                )
                sys.stdout.write(status)
                sys.stdout.flush()

    try:
        while sel.get_map():
            wait_sec = 0.25
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    proc.wait()
                    if show_live:
                        sys.stdout.write("\r\033[K")
                        sys.stdout.flush()
                    raise CommandError(display, 124, f"timed out after {timeout} seconds")
                if remaining < wait_sec:
                    wait_sec = remaining

            events = sel.select(timeout=wait_sec)
            if not events and show_live:
                now_t = time.monotonic()
                if now_t - last_draw >= 1.0:
                    last_draw = now_t
                    elapsed_s = int(now_t - started)
                    sys.stdout.write(
                        f"\r\033[K{_paint('[*]', _CYAN)} {stream_label} "
                        f"[{elapsed_s // 60:02d}:{elapsed_s % 60:02d}] working..."
                    )
                    sys.stdout.flush()

            for key, _mask in events:
                tag = str(key.data)
                fileobj = key.fileobj
                chunk = os.read(fileobj.fileno(), 4096)  # type: ignore[union-attr]
                if not chunk:
                    sel.unregister(fileobj)
                    if buffers[tag]:
                        _emit_line(tag, bytes(buffers[tag]))
                        buffers[tag].clear()
                    continue
                buffers[tag].extend(chunk)
                while True:
                    nl = buffers[tag].find(b"\n")
                    if nl < 0:
                        break
                    raw_line = bytes(buffers[tag][:nl])
                    del buffers[tag][: nl + 1]
                    _emit_line(tag, raw_line)
    finally:
        sel.close()
        proc.stdout.close()
        proc.stderr.close()

    returncode = proc.wait()
    if show_live:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    stdout_str = "\n".join(collected["STDOUT"]) + ("\n" if collected["STDOUT"] else "")
    stderr_str = "\n".join(collected["STDERR"]) + ("\n" if collected["STDERR"] else "")
    return returncode, stdout_str, stderr_str


def run(
    cmd,
    *,
    input_data: str | bytes | None = None,
    readonly: bool = False,
    check: bool = True,
    env_extra: dict[str, str] | None = None,
    timeout: int | None = None,
    cwd: str | None = None,
    stream_label: str | None = None,
) -> Result:
    """Run a command, log raw command + output (secrets redacted), and return Result."""
    if isinstance(cmd, (list, tuple)):
        argv = [str(part) for part in cmd]
        display = shlex.join(argv)
    else:
        argv = shlex.split(str(cmd))
        display = str(cmd)

    if DRY_RUN and not readonly:
        log.debug(f"DRY-RUN  {display}")
        return Result(display, 0, "", "")

    log.debug(f"CMD      {display}")
    started = time.monotonic()

    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)

    if input_data is None:
        returncode, stdout, stderr = _run_streaming_pipes(
            argv,
            display,
            cwd=cwd,
            env=env,
            timeout=timeout,
            stream_label=stream_label,
        )
        elapsed = time.monotonic() - started
        log.debug(f"EXIT     {returncode} ({elapsed:.1f}s)")
    else:
        payload = input_data.encode() if isinstance(input_data, str) else input_data
        try:
            proc = subprocess.run(
                argv,
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise CommandError(display, 127, f"executable not found: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandError(display, 124, f"timed out after {timeout} seconds") from exc

        elapsed = time.monotonic() - started
        returncode = proc.returncode
        stdout = proc.stdout.decode(errors="replace")
        stderr = proc.stderr.decode(errors="replace")

        log.debug(f"EXIT     {returncode} ({elapsed:.1f}s)")
        for line in stdout.splitlines():
            log.debug(f"STDOUT | {line[:2000]}")
        for line in stderr.splitlines():
            log.debug(f"STDERR | {line[:2000]}")

    if check and returncode != 0:
        tail = "\n".join(stderr.splitlines()[-15:])
        if not tail:
            tail = "\n".join(stdout.splitlines()[-15:])
        raise CommandError(display, returncode, log.redact(tail))

    return Result(display, returncode, stdout, stderr)


def run_with_retry(
    cmd,
    *,
    attempts: int = 3,
    delay_sec: float = 3.0,
    **kwargs,
) -> Result:
    """Retry transient CommandErrors (e.g. Arch ISO Wi-Fi mirror hiccups)."""
    total = max(1, attempts)
    for attempt in range(1, total + 1):
        try:
            return run(cmd, **kwargs)
        except CommandError as exc:
            if attempt >= total:
                raise
            warn(
                f"Command failed (attempt {attempt}/{total}, exit {exc.returncode}); "
                f"retrying in {delay_sec:.0f}s..."
            )
            if delay_sec > 0 and not DRY_RUN:
                time.sleep(delay_sec)
    raise AssertionError("unreachable")


def write_text(
    path: str | Path,
    content: str,
    *,
    mode: int | None = None,
    owner: tuple[int, int] | None = None,
    append: bool = False,
) -> None:
    target = Path(path)
    if DRY_RUN:
        log.debug(f"DRY-RUN  write {target} ({len(content)} bytes)")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a" if append else "w", encoding="utf-8") as handle:
        handle.write(content)
    if mode is not None:
        target.chmod(mode)
    if owner is not None:
        os.chown(target, owner[0], owner[1])
    log.debug(f"WRITE    {target} ({len(content)} bytes)")


def patch_file(
    path: str | Path,
    transform: Callable[[str], str],
    *,
    mode: int | None = None,
    default_if_missing: str | None = None,
) -> bool:
    """Apply an in-place line-patching transform without replacing unrelated lines."""
    target = Path(path)
    if DRY_RUN:
        log.debug(f"DRY-RUN  patch {target}")
        return True
    if target.exists():
        original = target.read_text(encoding="utf-8")
    elif default_if_missing is not None:
        original = default_if_missing
    else:
        warn(f"patch skipped; file not found: {target}")
        return False

    updated = transform(original)
    if updated == original and target.exists():
        log.debug(f"PATCH    {target} (unchanged)")
        return True

    write_text(target, updated, mode=mode)
    log.debug(f"PATCH    {target} (updated)")
    return True


def mkdir(path: str | Path, mode: int = 0o755) -> None:
    target = Path(path)
    if DRY_RUN:
        log.debug(f"DRY-RUN  mkdir {target}")
        return
    target.mkdir(parents=True, exist_ok=True)
    try:
        target.chmod(mode)
    except PermissionError:
        pass
    log.debug(f"MKDIR    {target}")


def copy(src: str | Path, dst: str | Path, *, mode: int | None = None) -> None:
    if DRY_RUN:
        log.debug(f"DRY-RUN  copy {src} -> {dst}")
        return
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    if mode is not None:
        Path(dst).chmod(mode)
    log.debug(f"COPY     {src} -> {dst}")


def ask(
    prompt: str,
    *,
    default: str | None = None,
    validator=None,
    error_message: str = "Invalid value, please try again.",
) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        try:
            raw = input(f"{_paint('?', _CYAN)} {prompt}{suffix}: ").strip()
        except EOFError as exc:
            raise ArchsetError("Input closed unexpectedly.") from exc
        if not raw and default is not None:
            raw = default
        if not raw:
            print(_paint("  value cannot be empty", _YELLOW))
            continue
        if validator is not None:
            is_valid, message = validator(raw)
            if not is_valid:
                print(_paint(f"  {message or error_message}", _YELLOW))
                continue
        return raw


def ask_password(
    prompt: str,
    *,
    confirm: bool = True,
    min_length: int = 8,
    allow_colon: bool = False,
) -> str:
    while True:
        try:
            first = getpass.getpass(f"{_paint('?', _CYAN)} {prompt}: ")
        except EOFError as exc:
            raise ArchsetError("Input closed unexpectedly.") from exc
        if len(first) < min_length:
            print(_paint(f"  password must be at least {min_length} characters", _YELLOW))
            continue
        if any(ord(char) < 32 for char in first) or (not allow_colon and ":" in first):
            msg = (
                "  the passphrase cannot contain control characters"
                if allow_colon
                else "  the password cannot contain ':' or control characters"
            )
            print(_paint(msg, _YELLOW))
            continue
        if confirm:
            second = getpass.getpass(f"{_paint('?', _CYAN)} confirm {prompt.lower()}: ")
            if first != second:
                print(_paint("  passwords do not match", _YELLOW))
                continue
        log.register_secret(first)
        log.debug(f"password captured for '{prompt}' (value redacted)")
        return first


def confirm(prompt: str, *, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            raw = input(f"{_paint('?', _CYAN)} {prompt} {hint}: ").strip().lower()
        except EOFError as exc:
            raise ArchsetError("Input closed unexpectedly.") from exc
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print(_paint("  please answer yes or no", _YELLOW))


def confirm_typed(prompt: str, expected: str) -> bool:
    print()
    print(_paint("Type the following text exactly to continue:", _BOLD))
    print(f"  {_paint(expected, _BOLD + _RED)}")
    try:
        value = input(f"{_paint('>', _RED)} ").strip()
    except EOFError as exc:
        raise ArchsetError("Input closed unexpectedly.") from exc
    if value != expected:
        log.warn(f"confirmation mismatch: expected {expected!r}")
        return False
    log.info(f"destructive operation confirmed: {prompt}")
    return True


def menu(
    title: str,
    items: list[str],
    *,
    default: int | None = None,
    subtitles: list[str] | None = None,
    zero_option: str | None = None,
) -> int:
    """Render a unified `[ N ] Option` menu (<= 76 cols).

    When ``zero_option`` is set, `[ 0 ] <zero_option>` is shown as the default
    continuation entry and returns ``-1`` when chosen.
    """
    print()
    hr("=", 76)
    print(_paint(f"  {title}", _BOLD + _CYAN))
    hr("-", 76)
    for index, item in enumerate(items, start=1):
        is_def = zero_option is None and default is not None and index - 1 == default
        marker = _paint("*", _GREEN + _BOLD) if is_def else " "
        tag = _paint(f"[ {index} ]", _BOLD + (_GREEN if is_def else _CYAN))
        print(f"  {marker} {tag} {item}")
        if subtitles and index - 1 < len(subtitles) and subtitles[index - 1]:
            print(_paint(f"          └─ {subtitles[index - 1]}", _DIM))
    if zero_option is not None:
        hr("-", 76)
        z_marker = _paint("*", _GREEN + _BOLD)
        z_tag = _paint("[ 0 ]", _BOLD + _GREEN)
        print(f"  {z_marker} {z_tag} {zero_option}")
    hr("=", 76)

    if zero_option is not None:
        range_lbl = f"0-{len(items)}"
        hint = " [0]"
    else:
        range_lbl = f"1-{len(items)}"
        hint = f" [{default + 1}]" if default is not None else ""

    while True:
        try:
            raw = input(
                f"{_paint('?', _CYAN)} Select option [{range_lbl}]{hint}: "
            ).strip()
        except EOFError as exc:
            raise ArchsetError("Input closed unexpectedly.") from exc
        if not raw:
            if zero_option is not None:
                return -1
            if default is not None:
                return default
            print(_paint("  please choose an option number", _YELLOW))
            continue
        if zero_option is not None and raw == "0":
            return -1
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return int(raw) - 1
        print(_paint("  invalid selection", _YELLOW))


def format_bytes(value: int) -> str:
    number = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if number < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(number)} {unit}"
            return f"{number:.1f} {unit}"
        number /= 1024
    return f"{value} B"
