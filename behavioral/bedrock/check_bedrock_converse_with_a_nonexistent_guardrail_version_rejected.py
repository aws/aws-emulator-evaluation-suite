"""bedrock-converse-with-a-nonexistent-guardrail-version-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-converse-with-a-nonexistent-guardrail-version-rejected"
GROUP = 'errors'
SERVICES = ['bedrock']

# ===== helpers =====

MODEL_ID = "amazon.nova-lite-v1:0"

_BLOCKED_IN = "sim2real-guardrail-refused-this-input-7c3e"
_BLOCKED_OUT = "sim2real-guardrail-refused-this-output-7c3e"
_READY_TIMEOUT_S = 120
_ABSENT_VERSION = "99"

_TOPIC_NAME = "sim2real-crypto-investment-advice"
_TOPIC_DEF = (
    "Requests for advice on which cryptocurrency to buy, sell or hold as an investment, "
    "including price predictions and portfolio allocation."
)
_PROMPT = "Name one primary colour. Answer in one word."


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
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY; "
        f"last status={status!r}"
    )


def _delete_guardrail(bc, gid):
    """Delete the guardrail and ALL its versions, retrying while a version delete is in flight.

    A per-version delete followed by a whole-guardrail delete leaves the guardrail briefly
    un-deletable, so the second delete raises and the guardrail is stranded. Deleting the guardrail
    alone cascades to its versions, so ONE registration is
    both sufficient and race-free; the bounded retry covers the residual conflict window.
    """
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


class _UnexpectedSuccess(AssertionError):
    """Raised when a call this check requires to be refused instead succeeds."""


def _error(fn):
    """The exact AWS error code and message, or a loud failure if the call SUCCEEDED.

    Never returns a falsy sentinel on success: an emulator accepting input real AWS rejects is the
    strongest possible signal and must not read as an error-code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise _UnexpectedSuccess(
        f"the call was expected to be refused but returned {result!r}"
    )


def _text(resp):
    return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])


@tags("axis:rejection", "concern:negative-classes", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """Converse refuses a guardrailConfig naming a guardrail version that does not exist, while the
    same request with guardrailVersion='DRAFT' succeeds: the refusal is about the version's
    existence, not its form.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = bc.create_guardrail(
        name=ctx.unique_name("sim2real-behav-gr-"),
        description="sim2real guardrail for a version-resolution negative",
        blockedInputMessaging=_BLOCKED_IN,
        blockedOutputsMessaging=_BLOCKED_OUT,
        topicPolicyConfig={"topicsConfig": [{
            "name": _TOPIC_NAME,
            "definition": _TOPIC_DEF,
            "examples": ["Should I buy bitcoin right now?"],
            "type": "DENY",
        }]},
        tags=[{"key": "sim2real", "value": "guardrail-absent-version"}],
    )
    gid = created["guardrailId"]
    ctx.on_cleanup(lambda: _delete_guardrail(bc, gid))
    _wait_ready(bc, gid)

    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    _wait_ready(bc, gid, version)

    versions = {v["version"] for v in _paginate_versions(bc, gid)}
    assert _ABSENT_VERSION not in versions, (
        f"the check's premise is that version {_ABSENT_VERSION!r} does not exist on {gid}; "
        f"ListGuardrails reported versions {sorted(versions)!r}"
    )

    # Break exactly one thing: the version number, on an otherwise identical request.
    code, message = _error(lambda: rt.converse(
        modelId=MODEL_ID,
        guardrailConfig={"guardrailIdentifier": gid, "guardrailVersion": _ABSENT_VERSION},
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig={"maxTokens": 20, "temperature": 0.0},
    ))
    assert code == "ValidationException", (
        f"a guardrailConfig naming a nonexistent version must be refused with "
        f"ValidationException; got {code!r}"
    )
    expected_message = "The guardrail identifier or version provided in the request does not exist."
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}; got {message!r}"
    )

    # Effect absent: the refusal did not disturb the guardrail or its published version.
    still = bc.get_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    assert still["status"] == "READY", (
        f"the refused inference must leave the published version untouched; GetGuardrail "
        f"reported status={still['status']!r}"
    )
    assert _ABSENT_VERSION not in {v["version"] for v in _paginate_versions(bc, gid)}, (
        f"the refused inference must not have created version {_ABSENT_VERSION!r}"
    )

    # Scoping control: DRAFT -- a version string that is not a number at all -- IS accepted, so
    # the refusal above is about resolution and not about the shape of the field.
    draft = rt.converse(
        modelId=MODEL_ID,
        guardrailConfig={"guardrailIdentifier": gid, "guardrailVersion": "DRAFT"},
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig={"maxTokens": 20, "temperature": 0.0},
    )
    assert draft["stopReason"] == "end_turn", (
        f"guardrailVersion='DRAFT' is accepted for inference on real AWS; got "
        f"{draft['stopReason']!r} text={_text(draft)!r}"
    )

    # Positive control: the byte-identical call with the published version succeeds.
    ok = rt.converse(
        modelId=MODEL_ID,
        guardrailConfig={"guardrailIdentifier": gid, "guardrailVersion": version},
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig={"maxTokens": 20, "temperature": 0.0},
    )
    assert ok["stopReason"] == "end_turn", (
        f"the same call with the published version {version!r} must succeed; got "
        f"{ok['stopReason']!r} text={_text(ok)!r}"
    )
    assert _text(ok).strip() and ok["usage"]["outputTokens"] > 0, (
        f"the positive control must return real generated text; usage={ok['usage']!r} "
        f"text={_text(ok)!r}"
    )


def _paginate_versions(bc, gid):
    """Every version of one guardrail, next-token looped.

    ListGuardrails has no paginator in botocore for this shape, and an account may hold many
    guardrails, so a single page is not a bound on the answer.
    """
    out, token = [], None
    while True:
        kw = {"guardrailIdentifier": gid, "maxResults": 100}
        if token:
            kw["nextToken"] = token
        page = bc.list_guardrails(**kw)
        out += page.get("guardrails") or []
        token = page.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
