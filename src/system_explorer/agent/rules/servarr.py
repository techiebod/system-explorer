"""servarr rules: the media managers' own self-diagnosis, mirrored.

Every Servarr app ships a health endpoint that states its problems in
typed items — indexers failing, download clients unreachable, root
folders missing — and a queue whose records carry the app's own verdict
on each download. The rules here MIRROR those severities rather than
invent thresholds: the app said it, the row repeats it, the evidence
cites the native members it came from. The two conditions the estate
adds are the ones the apps cannot state about themselves: an instance
that is named in configuration but missing its receipts, and an
instance that stopped answering at all.
"""

from __future__ import annotations

from .. import envelope as env

# The app's own health item severities; anything unrecognised mirrors as
# warn rather than being dropped (an unknown severity is still the app
# raising its hand).
HEALTH_ERROR = "error"
# Queue verdicts the app renders per record; ok is silence.
QUEUE_ATTENTION = ("warning", "error")


def app_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    if facts.get("ConfigDuplicate"):
        opinions.append(env.opinion(
            "servarr-duplicate", "warn",
            "SE_SERVARR_INSTANCES names this instance more than once; the"
            " first entry won and these were dropped: "
            + ", ".join(facts["ConfigDuplicate"]) + ".",
            ["ConfigDuplicate"]))
    if facts.get("ConfigMissing"):
        opinions.append(env.opinion(
            "servarr-unconfigured", "warn",
            "The instance is named in SE_SERVARR_INSTANCES but its"
            " receipts are missing: " + ", ".join(facts["ConfigMissing"])
            + ".", ["ConfigMissing"]))
        return opinions
    if facts.get("StatusUnobservable"):
        opinions.append(env.opinion(
            "servarr-unreachable", "critical",
            "The configured instance did not answer its API.",
            ["App", "StatusUnobservable"]))
        return opinions
    errors = facts.get("HealthErrors")
    warnings = facts.get("HealthWarnings")
    if isinstance(errors, int) and errors > 0:
        opinions.append(env.opinion(
            "servarr-health", "critical",
            f"The app reports {errors} health error(s) of its own — each"
            " is a row on the health collection.",
            ["HealthErrors"]))
    elif isinstance(warnings, int) and warnings > 0:
        opinions.append(env.opinion(
            "servarr-health", "warn",
            f"The app reports {warnings} health warning(s) of its own —"
            " each is a row on the health collection.",
            ["HealthWarnings"]))
    return opinions


def health_opinions(facts: dict) -> list[dict]:
    kind = facts.get("Type")
    if not kind or not facts.get("Message"):
        return []
    if kind == "ok":
        # The app filing a passing check as an item: nothing to mirror.
        return []
    # The apps' own grade ladder is ok/notice/warning/error; notice is
    # below-attention by their definition and mirrors as info, error as
    # critical, warning — and any grade this code has never heard of,
    # which is still the app raising its hand — as warn.
    level = ("critical" if kind == HEALTH_ERROR
             else "info" if kind == "notice" else "warn")
    return [env.opinion(
        "servarr-health-item", level,
        str(facts["Message"]), ["Type", "Message"])]


def queue_opinions(facts: dict) -> list[dict]:
    verdict = facts.get("TrackedDownloadStatus")
    if verdict not in QUEUE_ATTENTION:
        return []
    detail = facts.get("ErrorMessage") or facts.get("StatusMessages")
    suffix = f": {detail}" if isinstance(detail, str) else "."
    evidence = ["TrackedDownloadStatus"] + [
        member for member in ("ErrorMessage", "StatusMessages")
        if member in facts]
    return [env.opinion(
        "queue-item-stuck", "warn",
        "The app marks this download " + str(verdict) + suffix, evidence)]
