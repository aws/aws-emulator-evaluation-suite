"""apply-guardrail-custom-word-match-named-in-assessment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-custom-word-match-named-in-assessment"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock']


_BLOCKED_IN = "sim2real-blocked-input-91ac"
_BLOCKED_OUT = "sim2real-blocked-output-91ac"
_READY_TIMEOUT_S = 180

# A nonsense token: it cannot collide with a managed word list or a content classifier, so a hit
# is attributable to the custom word policy and nothing else.
_WORD = "zorblatt"
_READY = ("READY", "FAILED")


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
        lambda s: s in _READY,
        timeout_s=_READY_TIMEOUT_S,
    )
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY; "
        f"last status={status!r}"
    )


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-gr-"))
    kwargs.setdefault("blockedInputMessaging", _BLOCKED_IN)
    kwargs.setdefault("blockedOutputsMessaging", _BLOCKED_OUT)
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _publish_version(bc, ctx, gid):
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    ctx.on_cleanup(
        lambda: bc.delete_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    )
    _wait_ready(bc, gid, version)
    return version


def _apply(rt, gid, version, text):
    """ApplyGuardrail: policy engine only, no model weights (not H1-bounded). One short sentence
    -- ApplyGuardrail bills per text unit."""
    try:
        return rt.apply_guardrail(
            guardrailIdentifier=gid,
            guardrailVersion=version,
            source="INPUT",
            content=[{"text": {"text": text}}],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "AccessDeniedException":
            raise AssertionError(
                "ApplyGuardrail -> AccessDeniedException. bedrock has been reachable in this "
                "sandbox only via AWS_BEARER_TOKEN_BEDROCK, not task-role IAM, so this is an "
                "ENVIRONMENT artifact and not an emulator fidelity signal."
            ) from exc
        raise


def _word_policy(resp):
    assessments = resp["assessments"]
    assert assessments, f"ApplyGuardrail.assessments must be non-empty; got {assessments!r}"
    return assessments[0].get("wordPolicy") or {}


def _custom_words(resp, **fields):
    entries = _word_policy(resp).get("customWords") or []
    return [e for e in entries if all(e.get(k) == v for k, v in fields.items())]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom word-policy guardrail blocks the configured word, names it under
    assessments[0].wordPolicy.customWords with action BLOCKED and returns the blocked messaging,
    while a sentence without the word passes.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = _create_guardrail(
        bc,
        ctx,
        description="sim2real custom word policy",
        wordPolicyConfig={"wordsConfig": [{"text": _WORD}]},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)

    stored = bc.get_guardrail(guardrailIdentifier=gid)
    words = (stored.get("wordPolicy") or {}).get("words") or []
    assert [w.get("text") for w in words] == [_WORD], (
        f"GetGuardrail.wordPolicy.words must round-trip exactly [{_WORD!r}]; got {words!r}"
    )

    version = _publish_version(bc, ctx, gid)

    resp = _apply(rt, gid, version, f"The {_WORD} is on the shelf.")
    assert resp["action"] == "GUARDRAIL_INTERVENED", (
        f"a configured custom word must intervene; action={resp['action']!r} "
        f"assessments={resp['assessments']!r}"
    )
    hits = _custom_words(resp, match=_WORD, action="BLOCKED")
    assert hits, (
        f"no wordPolicy.customWords entry with match={_WORD!r} action=BLOCKED "
        f"(config has no action verb; the assessment verb is BLOCKED); "
        f"assessments[0]={resp['assessments'][0]!r}"
    )
    texts = [o.get("text") for o in resp["outputs"]]
    assert _BLOCKED_IN in " ".join(t for t in texts if t), (
        f"a blocked word must return the configured blockedInputMessaging {_BLOCKED_IN!r}; "
        f"got {texts!r}"
    )

    # Control: a sentence without the word must pass through the SAME version untouched, and the
    # word-policy assessment must report no block.
    control = _apply(rt, gid, version, "The kettle is on the shelf.")
    assert control["action"] == "NONE", (
        f"text without the configured word must not intervene; action={control['action']!r} "
        f"assessments={control['assessments']!r}"
    )
    assert not _custom_words(control, action="BLOCKED"), (
        f"control text produced a BLOCKED customWords assessment: {control['assessments']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
