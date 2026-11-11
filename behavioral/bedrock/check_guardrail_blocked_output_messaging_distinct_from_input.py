"""guardrail-blocked-output-messaging-distinct-from-input."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardrail-blocked-output-messaging-distinct-from-input"
GROUP = "guardrail_enforcement"
SERVICES = ["bedrock"]

# ApplyGuardrail on a freshly published version may briefly answer ResourceNotFoundException;
# _apply retries only that code.

# ===== helpers =====

# Deliberately different strings, and neither is a substring of the other, so a target that returns
# the wrong one cannot satisfy a containment assertion by accident.
_BLOCKED_IN = "sim2real refuses this request."
_BLOCKED_OUT = "sim2real withholds that answer."
_READY_TIMEOUT_S = 180
_APPLY_TIMEOUT_S = 120.0

_WORD = "grendlemarsh"


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
    kwargs.setdefault("tags", [{"key": "sim2real", "value": "guardrail-blocked-messaging"}])
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


def _apply(rt, gid, version, text, source):
    deadline = time.monotonic() + _APPLY_TIMEOUT_S
    while True:
        try:
            return rt.apply_guardrail(
                guardrailIdentifier=gid,
                guardrailVersion=version,
                source=source,
                content=[{"text": {"text": text}}],
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            assert time.monotonic() < deadline, (
                f"guardrail {gid} version={version!r} was READY on the control plane but "
                f"ApplyGuardrail kept reporting it absent for {_APPLY_TIMEOUT_S}s"
            )
            time.sleep(5.0)


def _blocked_words(resp):
    assessments = resp["assessments"]
    assert assessments, f"ApplyGuardrail.assessments must be non-empty; got {assessments!r}"
    entries = (assessments[0].get("wordPolicy") or {}).get("customWords") or []
    return [e.get("match") for e in entries if e.get("action") == "BLOCKED"]


def _texts(resp):
    return [o.get("text") for o in resp["outputs"]]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The refusal strings are direction-specific: a blocked INPUT returns blockedInputMessaging and a
    blocked OUTPUT returns blockedOutputsMessaging (as read back with GetGuardrail), never the other;
    benign controls show the guardrail does not refuse everything.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = _create_guardrail(
        bc,
        ctx,
        description="sim2real: distinct input and output refusal strings, one blocked word",
        wordPolicyConfig={"wordsConfig": [{"text": _WORD}]},
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)
    version = _publish_version(bc, ctx, gid)

    # The expected refusal strings come from the TARGET, not from the constants above.
    stored = bc.get_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    want_in = stored["blockedInputMessaging"]
    want_out = stored["blockedOutputsMessaging"]
    assert want_in != want_out, (
        f"the published version must carry two distinct refusal strings for this check to mean "
        f"anything; GetGuardrail returned {want_in!r} for both directions"
    )
    assert want_in not in want_out and want_out not in want_in, (
        f"neither stored refusal string may be a substring of the other, otherwise a wrong answer "
        f"could satisfy a containment test; got {want_in!r} and {want_out!r}"
    )

    offending = f"The {_WORD} was mentioned in passing."
    benign = "The kettle was mentioned in passing."

    # INPUT direction.
    as_input = _apply(rt, gid, version, offending, "INPUT")
    assert as_input["action"] == "GUARDRAIL_INTERVENED", (
        f"a configured blocked word must intervene on source=INPUT; action="
        f"{as_input['action']!r} assessments={as_input['assessments']!r}"
    )
    assert _blocked_words(as_input) == [_WORD], (
        f"the INPUT assessment must name {_WORD!r} as BLOCKED; got {as_input['assessments']!r}"
    )
    in_texts = _texts(as_input)
    assert want_in in in_texts, (
        f"a blocked INPUT must return the stored blockedInputMessaging {want_in!r} as one exact "
        f"output element; got {in_texts!r}"
    )
    assert want_out not in " ".join(t for t in in_texts if t), (
        f"a blocked INPUT must not return the OUTPUT-side refusal string {want_out!r}; got "
        f"{in_texts!r} (an emulator carrying one refusal string for both directions fails here)"
    )

    # OUTPUT direction: same text, same guardrail version, one field different.
    as_output = _apply(rt, gid, version, offending, "OUTPUT")
    assert as_output["action"] == "GUARDRAIL_INTERVENED", (
        f"a configured blocked word must intervene on source=OUTPUT too; action="
        f"{as_output['action']!r} assessments={as_output['assessments']!r}"
    )
    assert _blocked_words(as_output) == [_WORD], (
        f"the OUTPUT assessment must name {_WORD!r} as BLOCKED; got {as_output['assessments']!r}"
    )
    out_texts = _texts(as_output)
    assert want_out in out_texts, (
        f"a blocked OUTPUT must return the stored blockedOutputsMessaging {want_out!r} as one exact "
        f"output element; got {out_texts!r}"
    )
    assert want_in not in " ".join(t for t in out_texts if t), (
        f"a blocked OUTPUT must not return the INPUT-side refusal string {want_in!r}; got "
        f"{out_texts!r}"
    )

    # The pair is the point: the identical text must come back with two DIFFERENT strings.
    assert in_texts != out_texts, (
        f"the identical text blocked on both sources returned the same output both times "
        f"({in_texts!r}), so the direction-specific messaging is not being applied"
    )

    # Controls on both directions, so the check cannot pass against a target that refuses
    # unconditionally.
    for source in ("INPUT", "OUTPUT"):
        control = _apply(rt, gid, version, benign, source)
        assert control["action"] == "NONE", (
            f"source={source}: benign text must not intervene on the same guardrail version; "
            f"action={control['action']!r} assessments={control['assessments']!r}"
        )
        assert control["outputs"] == [], (
            f"source={source}: a non-intervening verdict returns no rewritten output; got "
            f"{control['outputs']!r}"
        )
        assert not _blocked_words(control), (
            f"source={source}: benign text produced a BLOCKED word assessment: "
            f"{control['assessments']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
