"""guardrail-detect-mode-reports-detection-without-blocking."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardrail-detect-mode-reports-detection-without-blocking"
GROUP = "guardrail_enforcement"
SERVICES = ["bedrock"]

_BLOCKED_IN = "sim2real detect-mode blocked input message."
_BLOCKED_OUT = "sim2real detect-mode blocked output message."
_READY_TIMEOUT_S = 180

# Nonsense tokens, so every hit is attributable to one word-policy entry.
_W_BLOCK = "zorblattine"
_W_DETECT = "quibbernaut"
_W_OFF = "flimbertosh"


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
    """Converge on a TERMINAL GuardrailStatus; ApplyGuardrail refuses a non-READY guardrail."""
    status = _poll(
        lambda: _guardrail_status(bc, gid, version),
        lambda s: s in ("READY", "FAILED"),
        timeout_s=_READY_TIMEOUT_S,
    )
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY within "
        f"{_READY_TIMEOUT_S}s; last status={status!r} (modeled GuardrailStatus: CREATING/UPDATING/"
        f"VERSIONING/READY/FAILED/DELETING)"
    )


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-gr-"))
    kwargs.setdefault("blockedInputMessaging", _BLOCKED_IN)
    kwargs.setdefault("blockedOutputsMessaging", _BLOCKED_OUT)
    kwargs.setdefault("tags", [{"key": "sim2real", "value": "guardrail-detect-mode"}])
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _publish_version(bc, ctx, gid):
    """CreateGuardrailVersion freezes the DRAFT; LIFO cleanup deletes the version first."""
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    ctx.on_cleanup(
        lambda: bc.delete_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    )
    _wait_ready(bc, gid, version)
    return version


def _apply(rt, gid, version, text):
    return rt.apply_guardrail(
        guardrailIdentifier=gid,
        guardrailVersion=version,
        source="INPUT",
        content=[{"text": {"text": text}}],
    )


def _custom_words(resp):
    """assessments[0].wordPolicy.customWords, hard-subscripting what is modelled @required."""
    assessments = resp["assessments"]
    assert assessments, f"ApplyGuardrail.assessments must be non-empty; got {assessments!r}"
    word_policy = assessments[0].get("wordPolicy") or {}
    return word_policy.get("customWords") or []


def _entry(resp, word):
    """The single customWords entry whose match is `word`, or None."""
    hits = [e for e in _custom_words(resp) if e.get("match") == word]
    assert len(hits) <= 1, (
        f"a single configured word must produce at most one customWords entry; got {hits!r}"
    )
    return hits[0] if hits else None


def _stored_words(stored):
    """{text: entry} from GetGuardrail's wordPolicy.words."""
    words = (stored.get("wordPolicy") or {}).get("words") or []
    return {w["text"]: w for w in words}


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Guardrail detect mode: inputAction=NONE detects without blocking, inputEnabled=False does not
    even detect, and both are distinguishable from inputAction=BLOCK on the same guardrail.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailWord.html
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = _create_guardrail(
        bc,
        ctx,
        description="sim2real word policy: one BLOCK, one detect-only, one disabled",
        wordPolicyConfig={
            "wordsConfig": [
                {"text": _W_BLOCK, "inputAction": "BLOCK", "inputEnabled": True},
                {"text": _W_DETECT, "inputAction": "NONE", "inputEnabled": True},
                # BLOCK on purpose: only inputEnabled=False keeps this word from blocking.
                {"text": _W_OFF, "inputAction": "BLOCK", "inputEnabled": False},
            ]
        },
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)

    stored = _stored_words(bc.get_guardrail(guardrailIdentifier=gid))
    assert sorted(stored) == sorted([_W_BLOCK, _W_DETECT, _W_OFF]), (
        f"GetGuardrail.wordPolicy.words must round-trip all three configured words "
        f"{sorted([_W_BLOCK, _W_DETECT, _W_OFF])!r}; got {sorted(stored)!r}"
    )
    assert stored[_W_DETECT].get("inputAction") == "NONE", (
        f"the detect-mode word must be stored with inputAction=NONE; got {stored[_W_DETECT]!r}"
    )
    assert stored[_W_BLOCK].get("inputAction") == "BLOCK", (
        f"the blocking word must be stored with inputAction=BLOCK; got {stored[_W_BLOCK]!r}"
    )
    assert stored[_W_OFF].get("inputEnabled") is False, (
        f"the disabled word must be stored with inputEnabled=False -- without this the absence of "
        f"an assessment below would be indistinguishable from the word never being configured; "
        f"got {stored[_W_OFF]!r}"
    )

    version = _publish_version(bc, ctx, gid)
    blocked_input = bc.get_guardrail(guardrailIdentifier=gid, guardrailVersion=version)[
        "blockedInputMessaging"
    ]

    a = _apply(rt, gid, version, f"The {_W_BLOCK} is on the shelf.")
    assert a["action"] == "GUARDRAIL_INTERVENED", (
        f"a word with inputAction=BLOCK must intervene; action={a['action']!r} "
        f"actionReason={a.get('actionReason')!r} assessments={a['assessments']!r}"
    )
    a_hit = _entry(a, _W_BLOCK)
    assert a_hit is not None and a_hit.get("action") == "BLOCKED", (
        f"expected a customWords entry match={_W_BLOCK!r} action=BLOCKED (config has no action verb "
        f"of its own; the assessment verb is BLOCKED); got {_custom_words(a)!r}"
    )
    a_texts = [o.get("text") for o in a["outputs"]]
    assert blocked_input in a_texts, (
        f"a blocked input must return the guardrail's OWN stored blockedInputMessaging "
        f"{blocked_input!r} as one output element; got {a_texts!r}"
    )

    b = _apply(rt, gid, version, f"The {_W_DETECT} is on the shelf.")
    assert b["action"] == "NONE", (
        f"a word with inputAction=NONE must be detected WITHOUT intervening; got "
        f"action={b['action']!r} actionReason={b.get('actionReason')!r} "
        f"outputs={b['outputs']!r} (an emulator that treats inputAction as decorative blocks here)"
    )
    assert b["outputs"] == [], (
        f"a non-intervening verdict must carry no rewritten output; got {b['outputs']!r}"
    )
    b_hit = _entry(b, _W_DETECT)
    assert b_hit is not None, (
        f"detect mode must still REPORT the detection: expected a customWords entry with "
        f"match={_W_DETECT!r}; got {_custom_words(b)!r}"
    )
    assert b_hit.get("action") == "NONE", (
        f"a detect-mode hit must carry the assessment action NONE, not BLOCKED; got {b_hit!r}"
    )
    assert b_hit.get("detected") is True, (
        f"a detect-mode hit is a DETECTION: detected must be True, which is what separates it from "
        f"the undetected case behavioral/bedrock-runtime/"
        f"check_apply_guardrail_interventions_scope_drops_undetected_policy.py covers; got {b_hit!r}"
    )

    # The detect-mode word in the same request proves the word policy ran on this text.
    c = _apply(rt, gid, version, f"The {_W_OFF} sat beside the {_W_DETECT} on the shelf.")
    assert c["action"] == "NONE", (
        f"a word whose evaluation is disabled must not block even though its inputAction is BLOCK; "
        f"got action={c['action']!r} actionReason={c.get('actionReason')!r} "
        f"assessments={c['assessments']!r}"
    )
    c_matches = [e.get("match") for e in _custom_words(c)]
    assert _W_DETECT in c_matches, (
        f"in-request positive control failed: the enabled detect-mode word {_W_DETECT!r} must be "
        f"reported for this text, otherwise the absence of {_W_OFF!r} proves nothing; got "
        f"{_custom_words(c)!r}"
    )
    assert _W_OFF not in c_matches, (
        f"inputEnabled=False must keep the evaluation out of the response entirely, yet "
        f"{_W_OFF!r} was reported; customWords={_custom_words(c)!r}"
    )

    d = _apply(rt, gid, version, "The kettle is on the shelf.")
    assert d["action"] == "NONE", (
        f"text carrying none of the configured words must not intervene; action={d['action']!r} "
        f"assessments={d['assessments']!r}"
    )
    assert not [e for e in _custom_words(d) if e.get("detected") is True], (
        f"control text produced a detected customWords entry: {_custom_words(d)!r}"
    )

    # Policy units count evaluation, not matches, so all four calls bill the same.
    units = {
        "block": a["usage"]["wordPolicyUnits"],
        "detect": b["usage"]["wordPolicyUnits"],
        "disabled": c["usage"]["wordPolicyUnits"],
        "control": d["usage"]["wordPolicyUnits"],
    }
    assert len(set(units.values())) == 1, (
        f"the four arms evaluated the same word policy and must bill identical wordPolicyUnits; "
        f"got {units!r}"
    )
    assert units["control"] >= 1, (
        f"a word policy that ran must bill at least one unit; got usage={d['usage']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
