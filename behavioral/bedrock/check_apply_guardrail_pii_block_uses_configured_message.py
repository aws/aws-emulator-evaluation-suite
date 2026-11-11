"""apply-guardrail-pii-block-uses-configured-message."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-pii-block-uses-configured-message"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock']


_BLOCKED_IN = "sim2real-blocked-input-8f21"
_BLOCKED_OUT = "sim2real-blocked-output-8f21"
_READY_TIMEOUT_S = 180


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


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-gr-"))
    kwargs.setdefault("blockedInputMessaging", _BLOCKED_IN)
    kwargs.setdefault("blockedOutputsMessaging", _BLOCKED_OUT)
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _publish_version(bc, ctx, gid):
    # No per-version cleanup: DeleteGuardrail without a version removes every version, and a
    # preceding version delete leaves the guardrail briefly un-deletable.
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    _wait_ready(bc, gid, version)
    return version


def _apply(rt, gid, version, text):
    """ApplyGuardrail on one short INPUT text (it bills per text unit)."""
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


def _pii_entries(resp, **fields):
    assessments = resp["assessments"]
    assert assessments, f"ApplyGuardrail.assessments must be non-empty; got {assessments!r}"
    entries = (assessments[0].get("sensitiveInformationPolicy") or {}).get("piiEntities") or []
    return [e for e in entries if all(e.get(k) == v for k, v in fields.items())]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PII BLOCK guardrail intervenes on an SSN with a BLOCKED assessment and returns the
    configured blockedInputMessaging verbatim, while benign text through the same version passes.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ApplyGuardrail.html"""
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = _create_guardrail(
        bc,
        ctx,
        description="sim2real PII block policy",
        sensitiveInformationPolicyConfig={
            "piiEntitiesConfig": [{"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"}]
        },
        tags=[{"key": "sim2real", "value": "guardrail-pii-block"}],
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)
    version = _publish_version(bc, ctx, gid)

    resp = _apply(rt, gid, version, "My SSN is 123-45-6789.")

    assert resp["action"] == "GUARDRAIL_INTERVENED", (
        f"a BLOCK hit must intervene; action={resp['action']!r} "
        f"assessments={resp['assessments']!r}"
    )
    hits = _pii_entries(resp, type="US_SOCIAL_SECURITY_NUMBER", action="BLOCKED")
    assert hits, (
        "no piiEntities entry with type=US_SOCIAL_SECURITY_NUMBER action=BLOCKED "
        f"(config verb is BLOCK, assessment verb is BLOCKED); "
        f"assessments[0]={resp['assessments'][0]!r}"
    )

    texts = [o.get("text") for o in resp["outputs"]]
    assert _BLOCKED_IN in " ".join(t for t in texts if t), (
        f"outputs must carry the configured blockedInputMessaging {_BLOCKED_IN!r}; "
        f"got {texts!r}"
    )

    after = bc.get_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    assert after["status"] == "READY", (
        f"an ApplyGuardrail block must not change guardrail state; status={after['status']!r}"
    )

    control = _apply(rt, gid, version, "The train arrives at nine.")
    assert control["action"] == "NONE", (
        f"benign text must not be blocked; action={control['action']!r} "
        f"assessments={control['assessments']!r}"
    )
    assert not _pii_entries(control, action="BLOCKED"), (
        f"benign text produced a BLOCKED assessment: {control['assessments']!r}"
    )
    control_texts = [o.get("text") for o in control["outputs"]]
    assert _BLOCKED_IN not in " ".join(t for t in control_texts if t), (
        f"benign text returned the blocked messaging: {control_texts!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
