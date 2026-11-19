#!/usr/bin/env python3
"""Terminal UI, logging and subprocess helpers for archset.

All installer output is written in English. Every command, its exit code and
its output are appended to the installation log. Secrets are never logged.
"""

from __future__ import annotations

import getpass
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

LOG_DIR = "/var/log/archset"
VERSION = "1.1.0"

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


class _Logger:
    def __init__(self) -> None:
        self.path: Path | None = None
        self._fh = None

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
        self._write("INFO", f"archset {VERSION} log started")
        return self.path

    def _write(self, level: str, message: str) -> None:
        if self._fh is None:
            return
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for line in str(message).splitlines() or [""]:
            self._fh.write(f"[{stamp}] {level:<8} {line}\n")
        self._fh.flush()

    def debug(self, message: str) -> None:
        self._write("DEBUG", message)

    def info(self, message: str) -> None:
        self._write("INFO", message)
        print(f"{_paint('[*]', _CYAN)} {message}", flush=True)

    def ok(self, message: str) -> None:
        self._write("OK", message)
        print(f"{_paint('[+]', _GREEN)} {message}", flush=True)

    def warn(self, message: str) -> None:
        self._write("WARN", message)
        print(f"{_paint('[!]', _YELLOW)} {message}", flush=True)

    def error(self, message: str) -> None:
        self._write("ERROR", message)
        print(f"{_paint('[x]', _RED)} {message}", flush=True)

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


def run(
    cmd,
    *,
    input_data: str | bytes | None = None,
    readonly: bool = False,
    check: bool = True,
    env_extra: dict[str, str] | None = None,
    timeout: int | None = None,
    cwd: str | None = None,
) -> Result:
    """Run a command, log it, and return its captured output.

    ``readonly=True`` marks commands that are safe during a dry run
    (lsblk, blkid, findmnt, ...). All other commands are skipped when
    ``DRY_RUN`` is enabled.
    """
    if isinstance(cmd, (list, tuple)):
        argv = [str(part) for part in cmd]
        display = shlex.join(argv)
    else:
        argv = shlex.split(str(cmd))
        display = str(cmd)

    if DRY_RUN and not readonly:
        log.debug(f"DRY-RUN  {display}")
        return Result(display, 0, "", "")

    log.debug(f"cmd      {display}")
    started = time.monotonic()

    if isinstance(input_data, str):
        payload: bytes | None = input_data.encode()
    else:
        payload = input_data

    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)

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
    stdout = proc.stdout.decode(errors="replace")
    stderr = proc.stderr.decode(errors="replace")

    log.debug(f"exit     {proc.returncode} ({elapsed:.1f}s)")
    for line in stdout.splitlines():
        log.debug(f"out | {line[:2000]}")
    for line in stderr.splitlines():
        log.debug(f"err | {line[:2000]}")

    if check and proc.returncode != 0:
        tail = "\n".join(stderr.splitlines()[-15:])
        if not tail:
            tail = "\n".join(stdout.splitlines()[-15:])
        raise CommandError(display, proc.returncode, tail)

    return Result(display, proc.returncode, stdout, stderr)


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
    log.debug(f"write    {target} ({len(content)} bytes)")


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
    log.debug(f"mkdir    {target}")


def copy(src: str | Path, dst: str | Path) -> None:
    if DRY_RUN:
        log.debug(f"DRY-RUN  copy {src} -> {dst}")
        return
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    log.debug(f"copy     {src} -> {dst}")


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
            ok, message = validator(raw)
            if not ok:
                print(_paint(f"  {message or error_message}", _YELLOW))
                continue
        return raw


def ask_password(
    prompt: str,
    *,
    confirm: bool = True,
    min_length: int = 8,
) -> str:
    while True:
        try:
            first = getpass.getpass(f"{_paint('?', _CYAN)} {prompt}: ")
        except EOFError as exc:
            raise ArchsetError("Input closed unexpectedly.") from exc
        if len(first) < min_length:
            print(_paint(f"  password must be at least {min_length} characters", _YELLOW))
            continue
        if ":" in first or any(ord(char) < 32 for char in first):
            print(
                _paint(
                    "  the password cannot contain ':' or control characters",
                    _YELLOW,
                )
            )
            continue
        if confirm:
            second = getpass.getpass(f"{_paint('?', _CYAN)} confirm {prompt.lower()}: ")
            if first != second:
                print(_paint("  passwords do not match", _YELLOW))
                continue
        log.debug("password captured (value intentionally not logged)")
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


def menu(title: str, items: list[str], *, default: int | None = None) -> int:
    print()
    print(_paint(title, _BOLD))
    for index, item in enumerate(items, start=1):
        marker = "*" if default is not None and index - 1 == default else " "
        print(f"  {marker} {index}) {item}")
    hint = f" [{default + 1}]" if default is not None else ""
    while True:
        try:
            raw = input(f"{_paint('?', _CYAN)} select [1-{len(items)}]{hint}: ").strip()
        except EOFError as exc:
            raise ArchsetError("Input closed unexpectedly.") from exc
        if not raw:
            if default is not None:
                return default
            print(_paint("  please choose a number", _YELLOW))
            continue
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
