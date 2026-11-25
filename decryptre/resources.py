"""OS scheduling priority and memory headroom helpers.

Large wordlist scans are CPU-bound in every worker, so at normal priority they
compete with foreground applications for CPU time. The scan is just as fast
when nothing else needs the machine, so the parent and every worker drop to
background priority by default.

Priority changes are best-effort: a platform or container that refuses them
still runs the scan at normal priority instead of failing.
"""

import os
from typing import Optional, Tuple

PRIORITY_CHOICES = ("normal", "background")

# Windows priority class flag used by SetPriorityClass and psutil.
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
POSIX_BACKGROUND_NICE = 10

# Tiers long enough that tight memory during the scan is worth a warning.
MEMORY_WARNING_TIERS = ("50m", "100m")

# Rough peak per worker: interpreter, parsed blob, in-flight chunk and results.
WORKER_MEMORY_BYTES = 64 * 1024 * 1024
PARENT_MEMORY_BYTES = 64 * 1024 * 1024


def _psutil():
    """Import psutil lazily so a missing install only disables niceties."""
    try:
        import psutil
    except ImportError:
        return None
    return psutil


def lower_priority(mode: str = "background") -> bool:
    """Drop this process to background priority; True when it was applied."""
    if mode != "background":
        return False
    psutil = _psutil()
    if psutil is not None:
        try:
            process = psutil.Process()
            if os.name == "nt":
                process.nice(
                    getattr(
                        psutil,
                        "BELOW_NORMAL_PRIORITY_CLASS",
                        BELOW_NORMAL_PRIORITY_CLASS,
                    )
                )
            else:
                process.nice(POSIX_BACKGROUND_NICE)
            return True
        except (psutil.Error, OSError, ValueError):
            pass
    return _lower_priority_fallback()


def _lower_priority_fallback() -> bool:
    """Best-effort priority drop when psutil is unavailable."""
    try:
        if os.name == "nt":
            import ctypes

            return bool(
                ctypes.windll.kernel32.SetPriorityClass(
                    ctypes.windll.kernel32.GetCurrentProcess(),
                    BELOW_NORMAL_PRIORITY_CLASS,
                )
            )
        if hasattr(os, "nice"):
            os.nice(POSIX_BACKGROUND_NICE)
            return True
    except Exception:
        return False
    return False


def available_memory() -> Optional[Tuple[int, int]]:
    """Return ``(available, total)`` RAM in bytes, or None if unreadable."""
    psutil = _psutil()
    if psutil is None:
        return None
    try:
        memory = psutil.virtual_memory()
    except psutil.Error:
        return None
    return int(memory.available), int(memory.total)


def estimate_scan_memory(workers: int) -> int:
    """Rough peak bytes for a streamed scan; independent of tier length."""
    return PARENT_MEMORY_BYTES + max(1, workers) * WORKER_MEMORY_BYTES


def _format_gib(value: int) -> str:
    return f"{value / (1024 ** 3):.1f} GiB"


def memory_warning(tier: str, workers: int) -> Optional[str]:
    """Warn when a long scan is likely to run out of RAM; never blocks."""
    if tier not in MEMORY_WARNING_TIERS:
        return None
    snapshot = available_memory()
    if snapshot is None:
        return None
    available, total = snapshot
    estimate = estimate_scan_memory(workers)
    if available >= estimate:
        return None
    return (
        f"warning: the {tier} tier with {workers} workers can need roughly "
        f"{_format_gib(estimate)} of RAM, but only {_format_gib(available)} is "
        f"available ({_format_gib(total)} total). Close other applications or "
        f"lower --workers to reduce memory use. The list itself is streamed, "
        f"so its length does not add memory."
    )
