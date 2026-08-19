"""The claim vm-lab stamps on a domain is a contract another repository reads.

These guests are disposable and they live on a KVM host that has a life of its
own. Anything auditing that host's domains against its own configuration finds
them unaccounted for and is right to — but "an orphan nobody meant to leave" and
"another tool's scratch VM" are different answers and only the first is
actionable, so a report that renders them identically invites deleting a lab
guest that is in use.

`vm-lab` therefore stamps a claim into the domain's own libvirt metadata, and
the homelab estate's vestige report reads it. That makes the shape a contract
between two repositories that do not share a test suite, and the consumer asked
for exactly two properties: a STABLE namespace URI, and the values as separate
keys rather than one blob it would have to version-match. This suite is what
stops either being changed by accident.

STATED COVERAGE, because it is narrower than it looks. This checks the claim's
SHAPE, statically, out of the script's own text. It does not and cannot check
that libvirt accepts the `virsh metadata` call — there is no libvirt here, and
the only host with one is an estate machine mid-rollout that this session was
asked not to write to. So the invocation itself is unexercised until a guest is
next rebuilt, and `stake_claim` is deliberately best-effort for that reason: a
libvirt too old for `virsh metadata` logs that the guest is unclaimed and lets
the lab come up, which is the pre-existing behaviour rather than a new failure.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "test" / "vm-lab" / "bin" / "vm-lab"

# The namespace the consumer keys on. Written here as a literal — the one place
# in this repository where restating the value is the point, because a test that
# read it from the script could not notice the script changing it.
EXPECTED_URI = "https://github.com/techiebod/system-explorer/vm-lab"

# What the estate's reader is entitled to find. `owner` names who parked the
# guest; `staked` is what lets a reader DISBELIEVE the claim, since a claim is
# an assertion and not a proof — a tool that died leaves one that reads healthy
# forever unless its age is visible.
REQUIRED_KEYS = ("owner", "staked")


def _claim_xml() -> str:
    """The claim the script builds, with its substitutions resolved.

    Read out of the script rather than by running it: the point is to pin what
    the file says, and running vm-lab needs a libvirt this suite does not have.
    """
    src = SCRIPT.read_text()
    match = re.search(r'^CLAIM_URI="([^"]+)"', src, re.M)
    assert match, (
        "vm-lab defines no CLAIM_URI — either the claim was removed, in which "
        "case the estate's vestige report silently goes back to listing these "
        "guests as drift, or it was renamed and this check now passes over "
        "nothing"
    )
    uri = match.group(1)
    parts = re.findall(r'^\s*claim\+?=(?:")(.*?)(?:")$', src, re.M)
    assert parts, "no claim body found in vm-lab; this check would prove nothing"
    claim = "".join(parts).replace("${CLAIM_URI}", uri).replace('\\"', '"')
    return re.sub(r"\$\(date[^)]*\)", "2026-01-01T00:00:00Z", claim)


CLAIM = _claim_xml()


def test_the_namespace_is_the_one_the_estate_reads() -> None:
    """A changed URI is a silent break: the consumer finds no claim and reports
    the guest as unaccounted for, which is the exact wrong answer this exists to
    prevent — and nothing fails on either side."""
    src = SCRIPT.read_text()
    assert f'CLAIM_URI="{EXPECTED_URI}"' in src, (
        f"vm-lab's claim namespace moved away from {EXPECTED_URI}. The estate's "
        "vestige report keys on it, so changing it makes every lab guest read "
        "as drift again, with no failure anywhere to say so. Coordinate the "
        "change with the homelab repository before landing it."
    )


def test_the_claim_is_well_formed_xml() -> None:
    """libvirt stores metadata as an XML element; a malformed one is refused at
    stamping time, on a host, long after this suite could have said so."""
    ElementTree.fromstring(CLAIM)


@pytest.mark.parametrize("key", REQUIRED_KEYS)
def test_each_value_is_its_own_element(key: str) -> None:
    """Separate keys, not one blob.

    The consumer asked for this specifically: it must be able to read `owner`
    and `staked` without knowing which version of this schema wrote them.
    Extra elements are free for it; a changed SHAPE is not, so collapsing these
    into a single string — or renaming one — has to fail here rather than in
    somebody else's report.

    Plain tag names, no namespace: libvirt binds the URI to CLAIM_KEY when it
    stores the element, and `virsh metadata --uri …` hands the consumer the
    readback, which is unprefixed. An earlier version of this test looked the
    children up IN the namespace — it passed, because it was checking the XML
    this script builds rather than the shape the consumer is given, and those
    are not the same document.
    """
    root = ElementTree.fromstring(CLAIM)
    element = root.find(key)
    assert element is not None, (
        f"the claim carries no <{key}> element of its own. The estate's reader "
        f"looks up {key} by name; a blob it has to parse positionally couples "
        "the two repositories to a schema version neither of them checks."
    )
    assert (element.text or "").strip(), f"<{key}> is present but empty"


def test_the_claim_carries_no_namespace_of_its_own() -> None:
    """libvirt supplies it, and declaring one here produced a mixed form.

    Passing `xmlns="…"` alongside `--key` made libvirt emit
    `<vm-lab xmlns:vmlab="…">` — an unprefixed element carrying a prefixed
    declaration nothing uses, which is nobody's intent and is not what the
    consumer's parser was described. Proven against a live libvirt on
    2026-08-19: with no xmlns, the domain stores `<vmlab:vm-lab>` with every
    child prefixed, and the readback is clean.
    """
    assert "xmlns" not in CLAIM, (
        "the claim declares its own namespace; libvirt binds CLAIM_URI to "
        "CLAIM_KEY and doing both yields a mixed form"
    )


def test_the_set_passes_the_namespace_key() -> None:
    """`virsh metadata --set` refuses without `--key`.

    "namespace key is required when modifying metadata" — and the first
    version of this omitted it, so every claim silently failed to stake while
    the lab came up green. The guard is here because that failure is invisible
    from this side: stake_claim is best-effort by design, so a missing --key
    costs a log line and nothing else.
    """
    src = SCRIPT.read_text()
    assert re.search(r'--key\s+"\$\{CLAIM_KEY\}"', src), (
        "stake_claim does not pass --key to `virsh metadata --set`, which "
        "refuses without it. The claim will never stake, and because the step "
        "is best-effort the only symptom is one log line."
    )


# What the claim is allowed to say. An ALLOWLIST, and the first draft of this
# file got it wrong in a way worth recording: it was written as a denylist of
# estate hostnames, which meant spelling those hostnames in a public repository
# — and the repo's own lint caught it, in the test whose entire purpose was to
# keep host names out. A denylist has to name what it forbids; an allowlist
# names only what this tool writes, and forbids everything else by saying
# nothing about it.
PERMITTED_TEXT = {
    "system-explorer vm-lab",
    "disposable conformance lab guest; rebuilt on demand",
}


def test_the_claim_says_only_what_this_tool_chose_to_say() -> None:
    """This repository is public, and a claim is stored ON the host it
    describes — so a reader is already there and a hostname would add nothing
    but a disclosure.

    Rather than enumerate what must not appear, every text value is held to a
    known set, with `staked` exempted because it is a timestamp generated at
    stamping time. Anything else added to the claim fails here and has to be
    added to the set deliberately, where somebody reviews whether it names the
    estate.
    """
    root = ElementTree.fromstring(CLAIM)
    for element in root:
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "staked":
            continue
        value = (element.text or "").strip()
        assert value in PERMITTED_TEXT, (
            f"the claim's <{tag}> carries {value!r}, which is not in this "
            "file's permitted set. If it is deliberate, add it there — and "
            "check first that it names no host, because a claim is read from "
            "the machine it sits on and this repository is public."
        )
