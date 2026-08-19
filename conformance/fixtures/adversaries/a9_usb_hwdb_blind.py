#!/usr/bin/env python3
"""Adversary fixture — hwdb-fallback-blind: a device's own strings never read.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. hardware/usb publishes a Vendor and a Product
from TWO sources in order — the udev hardware database's name for the vendor
and product ids, and, where the database has neither, the strings the device
reports about ITSELF in sysfs. A port that reads the database and stops
publishes a USB device with no maker and no model on any host whose udev has no
usb.ids, which is every minimal image this product will ever be run on.

Expected verdict: GREEN on every committed pair, forever — and that green is
the point, not a gap. Every USB device in corpus/hardware/qemu-guest is a
Linux Foundation root hub, which the hardware database knows perfectly well, so
the fallback is reached by nothing and dropping it changes not one byte the
replay judge can see. This is DESIGN 20's third trap: replay equivalence proves
a collector right about the machines the corpus holds and nothing else, and a
fallback no capture exercises is a fallback a port can simply not have. The
subject's RED lives in conformance/test_differential.py, where the
`usb-hwdb-miss` operator strips the two database members and puts the hubs'
own sysfs strings in their place, exactly as a host with no usb.ids would.

**Why this delegates.** The usb derivation is small but it is not the artefact;
the artefact is one fallback never taken. A hand-rolled second port would
disagree about the interface filter, about the device/hub split, about which
sysfs attributes are read at all, and prove nothing about the defect. So this
IS the reference, run against a payload whose fallback has been made
unreachable before the reference ever sees it: the two sysfs attributes the
fallback would read are rewritten to null — the tree seam's own spelling for
"there is no such file" — so the output is byte-for-byte what a hwdb-only port
emits, and the difference from a correct port is precisely the facts it should
have published. On the committed capture, where the fallback is never reached
because the database answered, the rewrite is a no-op, which is what makes the
green honest rather than an accident of agreement.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# The tree payload holding every file the walk opened, and the two attributes
# the hwdb fallback reads. Naming the payload keeps the rewrite from touching
# the udev replies, the listings or the link targets — the blindness is the
# fallback's alone.
BLIND_PAYLOAD = "read.json"
USB_TREE = "/sys/bus/usb/devices/"
BLIND_ATTRIBUTES = ("manufacturer", "product")


def _blind_reads(document: object) -> object:
    """The two sysfs attributes rewritten to null under every usb device
    directory, which is what a port that never asked for them had in hand.

    Null and not deleted: a key the capture does not hold is an UNCAPTURED
    read and the seam refuses it, which would be a refusal about the harness
    rather than a disagreement about the machine. Null is the captured answer
    "there is no such file", and it is what the fallback branch sees.
    """
    if not isinstance(document, dict):
        return document
    for container, attributes in document.items():
        if not container.startswith(USB_TREE) or not isinstance(attributes, dict):
            continue
        for name in BLIND_ATTRIBUTES:
            if name in attributes:
                attributes[name] = None
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and blind the two attributes
    # before the reference reads them. Every file is copied, not just the one
    # rewritten: the tree seam refuses a path no document holds, so a directory
    # missing listdir.json or realpath.json is a broken capture rather than a
    # blind port.
    with tempfile.TemporaryDirectory(prefix="se-hwdb-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                document = _blind_reads(json.loads(payload.read_text()))
                (directory / payload.name).write_text(json.dumps(document, indent=1))
            else:
                shutil.copy(payload, directory / payload.name)
        env = dict(os.environ)
        env["SE_REPLAY_DIR"] = str(directory)
        proc = subprocess.run(
            [sys.executable, str(REF)],
            input=sys.stdin.read(),
            capture_output=True,
            text=True,
            env=env,
        )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    sys.stdout.write(proc.stdout)


if __name__ == "__main__":
    main()
