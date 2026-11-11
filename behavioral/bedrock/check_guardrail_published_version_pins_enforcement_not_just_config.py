"""guardrail-published-version-pins-enforcement-not-just-config."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardrail-published-version-pins-enforcement-not-just-config"
GROUP = "guardrails"
SERVICES = ["bedrock"]

# UpdateGuardrail's wordPolicyConfig replaces the whole policy. The DRAFT's runtime view is
# eventually consistent, so the arm that must CHANGE is converged first, then the arm that must not.
# ApplyGuardrail on a freshly published version may briefly answer ResourceNotFoundException;
# _apply retries only that code.

# ===== helpers =====

_BLOCKED_IN = "sim2real version-pinning blocked input message."
_BLOCKED_OUT = "sim2real version-pinning blocked output message."
_READY_TIMEOUT_S = 180
_CONVERGE_TIMEOUT_S = 120.0

# Nonsense tokens so a hit is attributable to the word policy and to one specific published state.
_W_V1 = "brindlewock"
_W_DRAFT = "spandrelith"


def _poll(fn, pred, *, timeout_s, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _guardrail_status(bc, gid, version=None):
    kw = {"guardrailIdentifier": gid}
    if version is not None:
        kw["guardrailVersion"] = version
    try:
        return bc.get_guardrail(**kw)["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "ABSENT"
        raise


def _wait_ready(bc, gid, version=None):
    status = _poll(
        lambda: _guardrail_status(bc, gid, version),
        lambda s: s in ("READY", "FAILED"),
        timeout_s=_READY_TIMEOUT_S,
    )
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY within "
        f"{_READY_TIMEOUT_S}s; last status={status!r}"
    )


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-gr-"))
    kwargs.setdefault("blockedInputMessaging", _BLOCKED_IN)
    kwargs.setdefault("blockedOutputsMessaging", _BLOCKED_OUT)
    kwargs.setdefault("tags", [{"key": "sim2real", "value": "guardrail-version-pinning"}])
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _publish_version(bc, ctx, gid):
    """Cleanups run LIFO, so registering the version delete AFTER the guardrail delete makes the
    version tear down FIRST."""
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    ctx.on_cleanup(
        lambda: bc.delete_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    )
    _wait_ready(bc, gid, version)
    return version


def _apply(rt, gid, version, text):
    """ApplyGuardrail with no model involved. A guardrail the control plane reports READY is
    briefly not yet applicable on the runtime endpoint; retry ONLY that, and only while the budget
    lasts."""
    deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    while True:
        try:
            return rt.apply_guardrail(
                guardrailIdentifier=gid,
                guardrailVersion=version,
                source="INPUT",
                content=[{"text": {"text": text}}],
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            assert time.monotonic() < deadline, (
                f"guardrail {gid} version={version!r} was READY on the control plane but "
                f"ApplyGuardrail kept reporting it absent for {_CONVERGE_TIMEOUT_S}s"
            )
            time.sleep(5.0)


def _blocked_words(resp):
    """The matched texts reported as BLOCKED in assessments[0].wordPolicy.customWords."""
    assessments = resp["assessments"]
    assert assessments, f"ApplyGuardrail.assessments must be non-empty; got {assessments!r}"
    entries = (assessments[0].get("wordPolicy") or {}).get("customWords") or []
    return [e.get("match") for e in entries if e.get("action") == "BLOCKED"]


def _sentence(word):
    return f"The {word} was left on the shelf."


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A published guardrail version pins ENFORCEMENT, not only the configuration a read returns: after
    the DRAFT swaps its blocked word, version 1 still blocks the old word and not the new one, while
    the DRAFT does the opposite, so a single current policy behind every version fails two arms.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    # CreateGuardrailResponse does not echo `name` and UpdateGuardrail requires it, so hold it.
    name = ctx.unique_name("sim2real-behav-gr-")
    created = _create_guardrail(
        bc,
        ctx,
        name=name,
        description="sim2real: v1 blocks one word, the DRAFT later blocks a different one",
        wordPolicyConfig={"wordsConfig": [{"text": _W_V1}]},
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)
    version = _publish_version(bc, ctx, gid)
    assert version != "DRAFT", (
        f"CreateGuardrailVersion must return a numbered version, not DRAFT; got {version!r}"
    )

    # Baseline: version 1 blocks the word it was published with. Establishing this BEFORE the update
    # is what makes arm (2) below mean "v1 was not repointed" rather than "v1 never blocked".
    before = _apply(rt, gid, version, _sentence(_W_V1))
    assert _blocked_words(before) == [_W_V1], (
        f"version {version} must block the word it was published with; blocked="
        f"{_blocked_words(before)!r} action={before['action']!r}"
    )

    # Swap the DRAFT's word policy entirely. wordPolicyConfig is a whole-policy replacement, so
    # after this the DRAFT knows only _W_DRAFT and version 1 knows only _W_V1.
    bc.update_guardrail(
        guardrailIdentifier=gid,
        name=name,
        blockedInputMessaging=_BLOCKED_IN,
        blockedOutputsMessaging=_BLOCKED_OUT,
        description="sim2real: the DRAFT now blocks a different word",
        wordPolicyConfig={"wordsConfig": [{"text": _W_DRAFT}]},
    )
    _wait_ready(bc, gid)

    # Converge the arm that MUST change, so the pinning claims below are made only after the update
    # has demonstrably reached the runtime. Raises on timeout -- a DRAFT that never picks up its own
    # edit is a failure, not a licence to proceed.
    deadline = time.monotonic() + _CONVERGE_TIMEOUT_S
    draft_new = _apply(rt, gid, "DRAFT", _sentence(_W_DRAFT))
    while _blocked_words(draft_new) != [_W_DRAFT]:
        assert time.monotonic() < deadline, (
            f"the DRAFT never began blocking its newly configured word {_W_DRAFT!r} within "
            f"{_CONVERGE_TIMEOUT_S}s of UpdateGuardrail returning and the DRAFT reporting READY; "
            f"last blocked={_blocked_words(draft_new)!r} action={draft_new['action']!r}"
        )
        time.sleep(5.0)
        draft_new = _apply(rt, gid, "DRAFT", _sentence(_W_DRAFT))
    assert draft_new["action"] == "GUARDRAIL_INTERVENED", (
        f"the converged DRAFT must intervene on {_W_DRAFT!r}; action={draft_new['action']!r}"
    )

    # (2) The pinned version must NOT have learned the DRAFT's new word.
    pinned_new = _apply(rt, gid, version, _sentence(_W_DRAFT))
    assert _blocked_words(pinned_new) == [], (
        f"version {version} was published before {_W_DRAFT!r} was ever configured and must not "
        f"block it; blocked={_blocked_words(pinned_new)!r} action={pinned_new['action']!r} "
        f"(an emulator that routes every evaluation through the current policy blocks here)"
    )
    assert pinned_new["action"] == "NONE", (
        f"version {version} must not intervene on a word it does not carry; "
        f"action={pinned_new['action']!r} assessments={pinned_new['assessments']!r}"
    )

    # (1) ...and must still enforce the word it WAS published with, after the DRAFT dropped it.
    pinned_old = _apply(rt, gid, version, _sentence(_W_V1))
    assert _blocked_words(pinned_old) == [_W_V1], (
        f"version {version} must still block {_W_V1!r} after the DRAFT removed it; blocked="
        f"{_blocked_words(pinned_old)!r} action={pinned_old['action']!r}"
    )

    # (4) The DRAFT must have LOST the old word -- the mirror image of (2), which catches a target
    #     that keeps one ever-growing union of every word the guardrail has ever named.
    draft_old = _apply(rt, gid, "DRAFT", _sentence(_W_V1))
    assert _blocked_words(draft_old) == [], (
        f"UpdateGuardrail replaced the whole word policy, so the DRAFT must no longer block "
        f"{_W_V1!r}; blocked={_blocked_words(draft_old)!r} action={draft_old['action']!r}"
    )
    assert draft_old["action"] == "NONE", (
        f"the DRAFT must not intervene on a word it no longer carries; "
        f"action={draft_old['action']!r} assessments={draft_old['assessments']!r}"
    )

    # The 2x2 must actually be a 2x2: the same text gets opposite verdicts from the two versions,
    # which is the property no single-version target can produce.
    assert pinned_old["action"] != draft_old["action"], (
        f"the identical text {_sentence(_W_V1)!r} must be blocked by version {version} and allowed "
        f"by the DRAFT; both returned action={pinned_old['action']!r}"
    )
    assert draft_new["action"] != pinned_new["action"], (
        f"the identical text {_sentence(_W_DRAFT)!r} must be blocked by the DRAFT and allowed by "
        f"version {version}; both returned action={draft_new['action']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
