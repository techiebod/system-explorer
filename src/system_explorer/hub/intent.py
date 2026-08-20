"""The estate's intent declaration, as the hub holds it (DESIGN 22, 16, 23).

One document per estate, held by every hub, hashed and compared when two
hubs federate. It is the only place in the product where somebody writes
down what *should* be true, and it is what turns self-evident judgement
into judgement against a purpose.

**The hash is over a canonical serialisation, not over the bytes.** The
collector contract hashes declaration BYTES, deliberately, because one
binary emits them and a re-serialisation there would be a different
declaration. Intent is the opposite case: the document is authored and
deployed independently at each site — this estate's from one repository,
a sibling's from its own configuration — so byte-identity is unavailable
and hashing bytes would refuse federation for ever over whitespace. What
canonicalising covers is key order and formatting.

**What it does NOT cover, stated because it will cost somebody a day
otherwise: array order is significant.** `objects`, `not_hosts` and a
plugin's stanzas are arrays, and two hubs listing the same members in
different orders hash differently and refuse to federate. Sorting them
here would assert that every array in an unknown plugin's stanza is a
set, which is not this file's to claim. So a deployment that generates
intent must generate it deterministically, and that is a constraint on
the generator rather than a bug in the comparison.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


class IntentInvalid(Exception):
    """The document cannot be used. Raised rather than defaulted: a hub
    running on a half-read intent would judge the estate against a
    purpose nobody stated."""


def canonical(document: Mapping[str, Any]) -> bytes:
    """Sorted keys, no insignificant whitespace, UTF-8. Array order is
    preserved — see the module docstring for why that is a constraint on
    whoever generates the document rather than something to fix here."""
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def intent_hash(document: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical(document)).hexdigest()


@dataclass(frozen=True)
class Denotation:
    """One host-local name that denotes an estate object."""

    host: str
    name: str
    #: None means host-native, never any-instance: a denotation matching
    #: every instance would merge them, which is acceptance item 1
    #: arriving through the intent document.
    instance: str | None = None

    @property
    def key(self) -> tuple[str, str | None, str]:
        return (self.host, self.instance, self.name)


@dataclass(frozen=True)
class EstateObject:
    id: str
    kind: str
    denoted_by: tuple[Denotation, ...]


@dataclass(frozen=True)
class Intent:
    document: Mapping[str, Any]
    hash: str
    estate: str
    revision: int
    reviewed: str
    estate_hub: str | None
    hosts: Mapping[str, Mapping[str, Any]]
    objects: tuple[EstateObject, ...]
    not_hosts: tuple[Mapping[str, Any], ...]
    reachability: tuple[Mapping[str, Any], ...]
    discovery: tuple[Mapping[str, Any], ...]
    plugins: Mapping[str, Mapping[str, Any]]

    @classmethod
    def load(cls, document: Mapping[str, Any]) -> "Intent":
        for member in ("schema", "estate", "revision", "reviewed", "membership"):
            if member not in document:
                raise IntentInvalid(f"intent carries no {member}")
        if document["schema"] != "se.intent/1":
            raise IntentInvalid(f"unknown intent schema {document['schema']!r}")
        membership = document["membership"]
        if not isinstance(membership, Mapping) or "hosts" not in membership:
            raise IntentInvalid("membership names no hosts")

        objects: list[EstateObject] = []
        # Keyed by (host, instance, name): the same tuple the checkpoint
        # carries, so a denotation and an object are compared on the same
        # terms rather than on two spellings of identity.
        seen: dict[tuple[str, str | None, str], str] = {}
        for raw in document.get("objects") or []:
            denotations = []
            for d in raw["denoted_by"]:
                denotation = Denotation(
                    host=d["host"], name=d["name"], instance=d.get("instance")
                )
                clash = seen.get(denotation.key)
                if clash is not None and clash != raw["id"]:
                    # Refused rather than resolved. Two estate objects
                    # denoted by one host-local name is a document that
                    # cannot be applied without choosing, and choosing is
                    # how two objects silently become one.
                    raise IntentInvalid(
                        f"{denotation.host}'s name {denotation.name!r} denotes both "
                        f"{clash!r} and {raw['id']!r}; a hub does not choose between them"
                    )
                seen[denotation.key] = raw["id"]
                denotations.append(denotation)
            objects.append(
                EstateObject(id=raw["id"], kind=raw["kind"], denoted_by=tuple(denotations))
            )

        return cls(
            document=document,
            hash=intent_hash(document),
            estate=document["estate"],
            revision=document["revision"],
            reviewed=document["reviewed"],
            estate_hub=document.get("estate_hub"),
            hosts=dict(membership["hosts"]),
            objects=tuple(objects),
            not_hosts=tuple(membership.get("not_hosts") or ()),
            reachability=tuple(document.get("reachability") or ()),
            discovery=tuple(membership.get("discovery") or ()),
            plugins=dict(document.get("plugins") or {}),
        )

    # -- estate identity (DESIGN 16) -------------------------------------

    def denotations(self) -> Mapping[tuple[str, str | None, str], str]:
        """(host, instance, native name) → estate object id.

        The ONLY way two hosts' native names become one object, and
        declaration rather than correlation on purpose. A pair absent from
        here is a host-scoped object and stays one — silence is not an
        invitation to correlate.
        """
        return {
            d.key: obj.id for obj in self.objects for d in obj.denoted_by
        }

    def denotes(self, host: str, name: str, instance: str | None = None) -> str | None:
        return self.denotations().get((host, instance, name))

    # -- membership (DESIGN 23) ------------------------------------------

    def declared_hosts(self) -> tuple[str, ...]:
        return tuple(sorted(self.hosts))

    def plugin(self, name: str) -> Mapping[str, Any] | None:
        """One plugin's stanza, verbatim and unvalidated.

        Unvalidated is the contract: the shape of a stanza is the
        plugin's declaration to state, and a hub that parsed it here
        would put the estate's concern back into this repository by
        another route. A caller that needs it checked asks the plugin.
        """
        return self.plugins.get(name)


def federation_refusal(local: Intent, remote_hash: str) -> str | None:
    """Why these two hubs may not merge, or None if they may.

    A hub hashes its intent, exchanges the hash on connect, and refuses
    while they differ — because two hubs federating from different
    declarations are describing different estates, and merging them
    silently mixes two worldviews.

    The refusal is legible by construction: it names both hashes, because
    "connection error" is what an operator cannot act on and "this site
    holds abc, the sibling holds def" is what they can.
    """
    if remote_hash == local.hash:
        return None
    return (
        f"this site holds intent {local.hash}, the sibling holds {remote_hash}; "
        f"the estate view is unavailable until they agree"
    )
