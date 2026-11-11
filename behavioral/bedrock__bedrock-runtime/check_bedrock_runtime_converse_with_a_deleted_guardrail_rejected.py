"""bedrock-runtime-converse-with-a-deleted-guardrail-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-converse-with-a-deleted-guardrail-rejected"
GROUP = 'overly-permissive'
SERVICES = ['bedrock', 'bedrock-runtime']

MODEL_ID = "amazon.nova-lite-v1:0"

_BLOCKED_IN = "sim2real-dg-refused-this-input-5a71"
_BLOCKED_OUT = "sim2real-dg-refused-this-output-5a71"
_READY_TIMEOUT_S = 180
_GONE_TIMEOUT_S = 180
_PROMPT = "Reply with exactly the single word PONG and nothing else."
_INFERENCE = {"maxTokens": 64, "temperature": 0.0}


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
    status = _poll(lambda: _guardrail_status(bc, gid, version),
                   lambda s: s in ("READY", "FAILED"), timeout_s=_READY_TIMEOUT_S)
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY; last status "
        f"{status!r}"
    )


def _error_code(fn):
    """Return (code, message), or RAISE if the call unexpectedly succeeded: success means
    unguarded generation for a caller who asked to be guarded, not a code mismatch."""
    try:
        resp = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code", ""),
                exc.response.get("Error", {}).get("Message", ""))
    raise AssertionError(
        f"Converse naming a DELETED guardrail SUCCEEDED. That is an over-permissiveness finding, "
        f"not a code mismatch: a caller that asked to be guarded was served unguarded output. "
        f"response={resp!r}"
    )


def _text(resp):
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a guardrail is deleted, Converse naming it is refused with ValidationException
    ("does not exist"), although the same call succeeded before the delete and the same prompt
    without a guardrail still generates.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-converse-api.html
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = bc.create_guardrail(
        name=ctx.unique_name("sim2real-behav-gr-"),
        description="sim2real guardrail deleted mid-flight",
        blockedInputMessaging=_BLOCKED_IN,
        blockedOutputsMessaging=_BLOCKED_OUT,
        # A word this prompt cannot produce: the guardrail must be a working no-op so the barrier
        # call is a real generation rather than an interception.
        wordPolicyConfig={"wordsConfig": [{"text": "zzqxwv"}]},
        tags=[{"key": "sim2real", "value": "guardrail-deleted-midflight"},
              {"key": "sim2real:managed", "value": "true"}],
    )
    gid = created["guardrailId"]
    # Registered immediately, before any assertion: if the barrier call below fails, the guardrail
    # must still be torn down. The in-band delete is the subject of the check, and this handler
    # swallows the resulting ResourceNotFoundException by design.
    ctx.on_cleanup(lambda: _delete_guardrail_if_present(bc, gid))
    _wait_ready(bc, gid)
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    _wait_ready(bc, gid, version)

    guardrail_config = {"guardrailIdentifier": gid, "guardrailVersion": version}
    messages = [{"role": "user", "content": [{"text": _PROMPT}]}]

    # Barrier: the guarded call WORKS. This is what makes the refusal below attributable to the
    # deletion rather than to propagation, an unusable guardrail, or a model outage.
    before = rt.converse(modelId=MODEL_ID, guardrailConfig=guardrail_config, messages=messages,
                         inferenceConfig=_INFERENCE)
    assert before["stopReason"] == "end_turn", (
        f"the guarded call must complete normally before the guardrail is deleted, else the "
        f"refusal proves nothing; got {before['stopReason']!r} text={_text(before)!r}"
    )
    assert "PONG" in _text(before).upper(), (
        f"the barrier call must be a real generation; got {_text(before)!r}"
    )

    # Break exactly one thing: delete the guardrail. Wait on the observable condition -- the
    # control plane reporting it gone -- never on a fixed sleep.
    bc.delete_guardrail(guardrailIdentifier=gid)
    gone = _poll(lambda: _guardrail_status(bc, gid), lambda s: s == "ABSENT",
                 timeout_s=_GONE_TIMEOUT_S)
    assert gone == "ABSENT", (
        f"GetGuardrail must stop resolving the deleted identifier before the data plane is "
        f"re-tested; last status {gone!r}"
    )

    code, message = _error_code(
        lambda: rt.converse(modelId=MODEL_ID, guardrailConfig=guardrail_config,
                            messages=messages, inferenceConfig=_INFERENCE)
    )
    assert code == "ValidationException", (
        f"Converse naming a deleted guardrail must be refused with ValidationException; got "
        f"{code!r} message={message!r}"
    )
    expected_message = (
        "The guardrail identifier or version provided in the request does not exist."
    )
    assert message == expected_message, (
        f"the refusal must say the guardrail identifier or version does not exist, so a caller "
        f"can tell it from a malformed request; expected {expected_message!r}, got {message!r}"
    )

    # The effect is absent: the control plane still reports the guardrail gone, so nothing was
    # recreated, and the version is unresolvable too.
    assert _guardrail_status(bc, gid) == "ABSENT", (
        f"the refused invocation must not have resurrected the guardrail record; "
        f"GetGuardrail returned {_guardrail_status(bc, gid)!r}"
    )
    assert _guardrail_status(bc, gid, version) == "ABSENT", (
        f"the published version must be gone with its guardrail; GetGuardrail(version="
        f"{version!r}) returned {_guardrail_status(bc, gid, version)!r}"
    )

    # Control: the identical prompt with no guardrailConfig still generates, so the refusal is
    # about the missing guardrail and not about the model or the account.
    unguarded = rt.converse(modelId=MODEL_ID, messages=messages, inferenceConfig=_INFERENCE)
    assert unguarded["stopReason"] == "end_turn", (
        f"the same prompt without a guardrail must still be answered, else the refusal above may "
        f"be a model outage; got {unguarded['stopReason']!r} text={_text(unguarded)!r}"
    )
    assert "PONG" in _text(unguarded).upper(), (
        f"the unguarded control produced no usable generation; got {_text(unguarded)!r}"
    )


def _delete_guardrail_if_present(bc, gid):
    """Idempotent teardown for the guardrail the check deletes in-band; on a failure path before
    that delete it is the only thing that removes the guardrail."""
    deadline = time.monotonic() + 60
    while True:
        try:
            bc.delete_guardrail(guardrailIdentifier=gid)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ThrottlingException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
