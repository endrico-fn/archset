#!/usr/bin/env python3
"""Stdlib-only hardware detection (CPU ucode, GPU KMS/drivers, VM, Wi-Fi, audio)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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
    gpus: frozenset[str]  # subset of {"intel", "amd", "nvidia", "vm"}
    is_vm: bool
    has_rtw88_wifi: bool
    has_intel_hda: bool

    def ucode_packages(self) -> list[str]:
        if self.is_vm:
            return []
        if self.cpu_vendor == "intel":
            return ["intel-ucode"]
        if self.cpu_vendor == "amd":
            return ["amd-ucode"]
        return []

    def initramfs_modules(self) -> list[str]:
        mods: list[str] = []
        if "intel" in self.gpus:
            mods.append("i915")
        if "amd" in self.gpus:
            mods.append("amdgpu")
        return mods

    def graphics_packages(self) -> list[str]:
        pkgs = ["mesa"]
        if "intel" in self.gpus:
            pkgs.extend(["intel-media-driver", "vulkan-intel", "libvpl"])
        if "amd" in self.gpus:
            pkgs.extend(["libva-mesa-driver", "vulkan-radeon"])
        return pkgs

    def multilib_gpu_packages(self) -> list[str]:
        pkgs: list[str] = []
        if "intel" in self.gpus:
            pkgs.append("lib32-vulkan-intel")
        if "amd" in self.gpus:
            pkgs.append("lib32-vulkan-radeon")
        if not pkgs:
            pkgs.append("lib32-mesa")
        return pkgs

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
        vm_tag = " [VM]" if self.is_vm else ""
        wifi_tag = " + rtw88" if self.has_rtw88_wifi else ""
        return f"CPU={self.cpu_vendor}, GPU={gpu_desc}{wifi_tag}{vm_tag}"


def _read_trimmed(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return ""


def detect(
    *,
    proc_cpuinfo: str | Path = "/proc/cpuinfo",
    pci_dir: str | Path = "/sys/bus/pci/devices",
    dmi_dir: str | Path = "/sys/class/dmi/id",
    modules_dir: str | Path = "/sys/module",
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
    has_rtw88 = False
    has_hda = False

    mod_root = Path(modules_dir)
    if (mod_root / "rtw88_core").exists() or (mod_root / "rtw88_pci").exists():
        has_rtw88 = True
    if (mod_root / "snd_hda_intel").exists():
        has_hda = True

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

            # PCI class 0x03xxxx = Display controller (VGA / 3D / Display)
            if pci_class.startswith("0x03"):
                if vendor == "0x8086":
                    gpus.add("intel")
                elif vendor == "0x1002":
                    gpus.add("amd")
                elif vendor == "0x10de":
                    gpus.add("nvidia")
                elif vendor in ("0x1af4", "0x1234", "0x15ad", "0x80ee"):
                    gpus.add("vm")

            # PCI class 0x0280xx = Network controller (Wireless)
            elif pci_class.startswith("0x0280") and vendor == "0x10ec":
                has_rtw88 = True

            # PCI class 0x0403xx = HD Audio controller
            elif pci_class.startswith("0x0403") and vendor in ("0x8086", "0x1022", "0x1002"):
                has_hda = True

    if not gpus:
        if is_vm:
            gpus.add("vm")
        elif cpu_vendor == "intel":
            gpus.add("intel")
        elif cpu_vendor == "amd":
            gpus.add("amd")

    return HardwareProfile(
        cpu_vendor=cpu_vendor,
        gpus=frozenset(gpus),
        is_vm=is_vm,
        has_rtw88_wifi=has_rtw88,
        has_intel_hda=has_hda,
    )
