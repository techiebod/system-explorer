"""System opinions: time synchronisation, boot health, host overview.

identity carries no opinions; time, boot and overview are single-object
collections whose observation attaches these evaluators' output directly, and
collect() derives the row from those same opinions. Generation pointers moved
to rules/nix.py with the subsystem that owns them.
The boot rules are presence-driven over the boot facts: EFI facts
(SecureBoot, BootEntries) simply do not exist on BIOS hosts, so those rules
never fire there. The overview rules are presence-driven the same way: a
kernel without CONFIG_PSI never carries the PSI facts, and a swapless host
carries SwapUsedPercent as null, so neither fires spuriously.
"""

from __future__ import annotations

from .. import envelope as env

# Host-snapshot thresholds (ROADMAP slice 1). Load is normalised per CPU;
# the PSI numbers are the kernel's own decaying 60-second stall shares
# (SPEC section 12: kernel-precomputed aggregates, no rates from counters).
LOAD_PER_CPU_WARN = 2.0
LOAD_PER_CPU_CRITICAL = 4.0
MEM_USED_WARN = 90
MEM_USED_CRITICAL = 95
SWAP_USED_WARN = 50
PSI_MEMORY_FULL_WARN = 5.0
PSI_MEMORY_FULL_CRITICAL = 20.0
PSI_CPU_SOME_WARN = 60.0
PSI_IO_FULL_WARN = 20.0


def time_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    if facts.get("NTP") and not facts.get("NTPSynchronized"):
        opinions.append(env.opinion(
            "time-sync", "warn",
            "NTP is enabled but the clock is not synchronised.",
            ["NTP", "NTPSynchronized"]))
    return opinions


def boot_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    if facts.get("SecureBoot"):
        opinions.append(env.opinion(
            "secure-boot", "warn",
            "Secure Boot is enabled: an unsigned boot chain (the NixOS "
            "systemd-boot default) will not boot while it is on.",
            ["SecureBoot"]))
    # Ordered entries whose target partition no longer resolves — Stale and
    # OrderPosition were both established per entry during acquisition.
    stale_in_order = [entry["ID"] for entry in (facts.get("BootEntries") or [])
                      if entry.get("Stale") and entry.get("OrderPosition") is not None]
    if stale_in_order:
        opinions.append(env.opinion(
            "boot-order-stale", "warn",
            "BootOrder references entries whose target partition no "
            "longer exists: " + ", ".join(stale_in_order) + ".",
            ["BootOrder", "BootEntries"]))
    if facts.get("BootNext"):
        opinions.append(env.opinion(
            "boot-next", "info",
            f"A one-shot boot override is armed: {facts['BootNext']} "
            "boots next, once.", ["BootNext"]))
    state = facts.get("SystemState")
    if state not in ("running", None):
        level = "critical" if state == "degraded" and facts.get("NFailedUnits") else "warn"
        opinions.append(env.opinion(
            "system-state", level,
            f"systemd reports state {state!r} with "
            f"{facts.get('NFailedUnits')} failed unit(s).",
            ["SystemState", "NFailedUnits"]))
    current = facts.get("CurrentSystem")
    if current and facts.get("SystemProfile") and current != facts["SystemProfile"]:
        opinions.append(env.opinion(
            "system-pointers", "warn",
            "The activated system is not the system profile (activated "
            "with 'test'?) — a reboot silently discards what is running now.",
            ["CurrentSystem", "SystemProfile"]))
    elif current and facts.get("BootedSystem") and current != facts["BootedSystem"]:
        opinions.append(env.opinion(
            "system-pointers", "info",
            "A switch has happened since boot; a reboot runs the new system "
            "fully (this is what defers a kernel change).",
            ["BootedSystem", "CurrentSystem"]))
    return opinions


def overview_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    load = facts.get("LoadPerCpu1")
    if load is not None and load >= LOAD_PER_CPU_WARN:
        opinions.append(env.opinion(
            "load-pressure",
            "critical" if load >= LOAD_PER_CPU_CRITICAL else "warn",
            f"Load is {load} runnable tasks per CPU (1-minute average "
            f"{facts.get('LoadAvg1')} over {facts.get('CpuCount')} CPUs).",
            ["LoadAvg1", "CpuCount"]))
    mem = facts.get("MemUsedPercent")
    if mem is not None and mem >= MEM_USED_WARN:
        # ZFS hosts: the ARC counts as "used" (Linux excludes it from
        # MemAvailable) yet shrinks under demand, so judge on ARC-adjusted
        # usage. Without the discount a cache-warm ZFS host reads as nearly
        # out of memory while PSI shows no stalling at all — a pressure that
        # does not exist (audit follow-up, 2026-08-10). The raw facts
        # are untouched; only the verdict discounts the cache, and the
        # message says so when it changes the outcome.
        arc = facts.get("ArcSizeBytes")
        total = facts.get("MemTotalBytes")
        used = facts.get("MemUsedBytes")
        adjusted = mem
        if arc and total and used is not None:
            adjusted = round(max(0, used - arc) * 100 / total)
        if adjusted >= MEM_USED_WARN:
            opinions.append(env.opinion(
                "memory-available",
                "critical" if adjusted >= MEM_USED_CRITICAL else "warn",
                f"Memory is {mem}% used; MemAvailable (what the kernel could "
                "reclaim without swapping) is nearly exhausted.",
                ["MemAvailableBytes", "MemTotalBytes"]))
        elif arc:
            opinions.append(env.opinion(
                "memory-available", "info",
                f"Memory reads {mem}% used, but {adjusted}% outside the ZFS "
                "ARC — the cache yields under demand, so this is occupancy, "
                "not pressure.",
                ["MemAvailableBytes", "MemTotalBytes", "ArcSizeBytes"]))
    swap = facts.get("SwapUsedPercent")
    if swap is not None and swap >= SWAP_USED_WARN:
        opinions.append(env.opinion(
            "swap-pressure", "warn",
            f"Swap is {swap}% used; memory demand has exceeded RAM.",
            ["SwapUsedBytes", "SwapTotalBytes"]))
    psi_mem = facts.get("PsiMemoryFullAvg60")
    if psi_mem is not None and psi_mem >= PSI_MEMORY_FULL_WARN:
        opinions.append(env.opinion(
            "psi-memory",
            "critical" if psi_mem >= PSI_MEMORY_FULL_CRITICAL else "warn",
            f"All non-idle tasks were stalled on memory {psi_mem}% of the "
            "last minute (thrashing).", ["PsiMemoryFullAvg60"]))
    psi_cpu = facts.get("PsiCpuSomeAvg60")
    if psi_cpu is not None and psi_cpu >= PSI_CPU_SOME_WARN:
        opinions.append(env.opinion(
            "psi-cpu", "warn",
            f"Tasks were waiting for CPU {psi_cpu}% of the last minute.",
            ["PsiCpuSomeAvg60"]))
    psi_io = facts.get("PsiIoFullAvg60")
    if psi_io is not None and psi_io >= PSI_IO_FULL_WARN:
        opinions.append(env.opinion(
            "psi-io", "warn",
            f"All non-idle tasks were stalled on I/O {psi_io}% of the "
            "last minute.", ["PsiIoFullAvg60"]))
    return opinions

