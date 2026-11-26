#!/usr/bin/env python3
"""Stdlib-only Intel hardware detection (CPU ucode, i915/xe KMS, HiDPI, Wi-Fi, audio)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import ui

VM_KEYWORDS = (
    "qemu",
    "kvm",
    "virtualbox",
    "innotek",
    "vmware",
    "bochs",
    "parallels",
    "xen",
    "bhyve",
)

MKINITCPIO_HOOKS = (
    "base systemd autodetect microcode modconf kms keyboard "
    "sd-vconsole block sd-encrypt sd-archrelius filesystems"
)


@dataclass(frozen=True)
class HardwareProfile:
    cpu_vendor: str  # "intel" | "amd" | "other"
    gpus: frozenset[str]  # subset of {"intel", "nvidia", "amd", "vm"}
    intel_drm_driver: str = "i915"  # "i915" | "xe" | ""
    is_vm: bool = False
    has_rtw88_wifi: bool = False
    has_intel_hda: bool = False
    has_sof_audio: bool = False
    has_nvidia_dgpu: bool = False
    max_panel_width: int = 0

    def assert_supported(self, *, allow_vm: bool = False) -> None:
        if allow_vm and self.is_vm:
            return
        if self.cpu_vendor != "intel":
            raise ui.ArchsetError(
                f"Unsupported CPU vendor '{self.cpu_vendor}': archset exclusively supports Intel hardware."
            )
        if "intel" not in self.gpus:
            gpu_desc = ",".join(sorted(self.gpus)) or "none"
            hint = " Pass --allow-vm when testing inside a virtual machine." if self.is_vm else ""
            raise ui.ArchsetError(
                f"Unsupported GPU configuration ({gpu_desc}): archset requires an Intel GPU.{hint}"
            )

    def ucode_packages(self) -> list[str]:
        if self.is_vm:
            return []
        if self.cpu_vendor == "intel":
            return ["intel-ucode"]
        return []

    def initramfs_modules(self) -> list[str]:
        if self.is_vm:
            return []
        if "intel" in self.gpus and self.intel_drm_driver in ("i915", "xe"):
            return [self.intel_drm_driver]
        return []

    def graphics_packages(self) -> list[str]:
        if "intel" in self.gpus and not self.is_vm:
            return [
                "mesa",
                "intel-media-driver",
                "vulkan-intel",
                "libvpl",
                "vpl-gpu-rt",
            ]
        return ["mesa"]

    def multilib_gpu_packages(self) -> list[str]:
        if "intel" in self.gpus and not self.is_vm:
            return ["lib32-mesa", "lib32-vulkan-intel"]
        return ["lib32-mesa"]

    def console_font(self) -> str:
        return "ter-v32n" if self.max_panel_width >= 2560 else "default8x16"

    def mkinitcpio_dropin(self) -> str:
        mods = " ".join(self.initramfs_modules())
        return (
            "# Managed by archset — overrides /etc/mkinitcpio.conf without touching upstream defaults.\n"
            "# Modern systemd-based initramfs with sd-encrypt + sd-archrelius (LUKS2 passphrase-only).\n"
            "# Keep 'base' before 'systemd' so an emergency rescue shell remains available.\n"
            f"MODULES=({mods})\n"
            f"HOOKS=({MKINITCPIO_HOOKS})\n"
        )

    def summary(self) -> str:
        gpu_desc = ",".join(sorted(self.gpus)) if self.gpus else "generic"
        if "intel" in self.gpus and self.intel_drm_driver and not self.is_vm:
            gpu_desc = f"{gpu_desc}({self.intel_drm_driver})"
        vm_tag = " [VM]" if self.is_vm else ""
        wifi_tag = " + rtw88" if self.has_rtw88_wifi else ""
        hidpi_tag = f" [{self.max_panel_width}px HiDPI]" if self.max_panel_width >= 2560 else ""
        return f"CPU={self.cpu_vendor}, GPU={gpu_desc}{wifi_tag}{hidpi_tag}{vm_tag}"


def assert_intel_hardware(profile: HardwareProfile, *, allow_vm: bool = False) -> None:
    profile.assert_supported(allow_vm=allow_vm)


def _read_trimmed(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return ""


def _bound_driver_name(dev: Path) -> str:
    try:
        target = os.readlink(dev / "driver")
    except OSError:
        return ""
    return Path(target).name.lower()


def _detect_max_panel_width(drm_root: Path) -> int:
    if not drm_root.is_dir():
        return 0
    max_w = 0
    try:
        entries = sorted(drm_root.iterdir())
    except OSError:
        return 0
    for entry in entries:
        modes_text = _read_trimmed(entry / "modes")
        for line in modes_text.splitlines():
            match = re.match(r"^\s*(\d+)x(\d+)", line)
            if match:
                width = int(match.group(1))
                if width > max_w:
                    max_w = width
    return max_w


def detect(
    *,
    proc_cpuinfo: str | Path = "/proc/cpuinfo",
    pci_dir: str | Path = "/sys/bus/pci/devices",
    dmi_dir: str | Path = "/sys/class/dmi/id",
    modules_dir: str | Path = "/sys/module",
    drm_dir: str | Path = "/sys/class/drm",
) -> HardwareProfile:
    cpu_text = _read_trimmed(Path(proc_cpuinfo))
    cpu_lower = cpu_text.lower()

    if "genuineintel" in cpu_lower:
        cpu_vendor = "intel"
    elif "authenticamd" in cpu_lower:
        cpu_vendor = "amd"
    else:
        cpu_vendor = "other"

    is_vm = False
    for line in cpu_lower.splitlines():
        if line.startswith("flags") and "hypervisor" in line.split():
            is_vm = True
            break

    dmi_root = Path(dmi_dir)
    for dmi_file in ("sys_vendor", "product_name", "board_vendor", "chassis_vendor"):
        val = _read_trimmed(dmi_root / dmi_file).lower()
        if val and any(kw in val for kw in VM_KEYWORDS):
            is_vm = True
            break

    gpus: set[str] = set()
    intel_drm_driver = ""
    has_rtw88 = False
    has_hda = False
    has_sof = False
    has_nvidia = False

    mod_root = Path(modules_dir)
    if (mod_root / "rtw88_core").exists() or (mod_root / "rtw88_pci").exists():
        has_rtw88 = True
    if (mod_root / "snd_hda_intel").exists():
        has_hda = True
    if mod_root.is_dir():
        try:
            for mod_entry in mod_root.iterdir():
                if mod_entry.name.startswith("snd_sof"):
                    has_sof = True
                    break
        except OSError:
            pass

    pci_root = Path(pci_dir)
    if pci_root.is_dir():
        try:
            entries = sorted(pci_root.iterdir())
        except OSError:
            entries = []
        for dev in entries:
            pci_class = _read_trimmed(dev / "class").lower()
            vendor = _read_trimmed(dev / "vendor").lower()
            if not pci_class or not vendor:
                continue
            driver = _bound_driver_name(dev)

            # PCI class 0x03xxxx = Display controller (VGA / 3D / Display)
            if pci_class.startswith("0x03"):
                if vendor == "0x8086":
                    gpus.add("intel")
                    if driver == "xe":
                        intel_drm_driver = "xe"
                    elif driver == "i915" and intel_drm_driver != "xe":
                        intel_drm_driver = "i915"
                elif vendor == "0x10de":
                    gpus.add("nvidia")
                    has_nvidia = True
                elif vendor == "0x1002":
                    gpus.add("amd")
                elif vendor in ("0x1af4", "0x1234", "0x15ad", "0x80ee"):
                    gpus.add("vm")

            # PCI class 0x0280xx = Wireless network controller (match bound rtw88 driver, not rtw89)
            elif pci_class.startswith("0x0280") and vendor == "0x10ec":
                if driver.startswith("rtw88"):
                    has_rtw88 = True

            # PCI class 0x0403xx / 0x0401xx = Intel HD Audio / Smart Sound (SOF)
            elif pci_class.startswith(("0x0403", "0x0401")) and vendor == "0x8086":
                if driver.startswith(("sof-", "snd_sof")):
                    has_sof = True
                elif driver == "snd_hda_intel":
                    has_hda = True
                else:
                    has_sof = True

    if not gpus:
        if is_vm:
            gpus.add("vm")
        elif cpu_vendor == "intel":
            gpus.add("intel")

    if "intel" in gpus and not is_vm and not intel_drm_driver:
        if (mod_root / "xe").exists():
            intel_drm_driver = "xe"
        else:
            intel_drm_driver = "i915"

    max_panel_width = _detect_max_panel_width(Path(drm_dir))

    return HardwareProfile(
        cpu_vendor=cpu_vendor,
        gpus=frozenset(gpus),
        intel_drm_driver=intel_drm_driver,
        is_vm=is_vm,
        has_rtw88_wifi=has_rtw88,
        has_intel_hda=has_hda,
        has_sof_audio=has_sof,
        has_nvidia_dgpu=has_nvidia,
        max_panel_width=max_panel_width,
    )
