"""apply-guardrail-response-shape."""
from __future__ import annotations


import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    import time as _t
    deadline = _t.monotonic() + timeout_s
    last = None
    while _t.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        _t.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", _unique_name("gr-"))
    kwargs.setdefault("blockedInputMessaging", "Input blocked by guardrail.")
    kwargs.setdefault("blockedOutputsMessaging", "Output blocked by guardrail.")
    kwargs.setdefault("tags", [{"key": "sim2real", "value": "apply-guardrail-response-shape"}])
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp

CHECK = "apply-guardrail-response-shape"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ApplyGuardrail returns usage, action, and outputs fields."""
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")
    # Create a guardrail with content filter
    create_resp = _create_guardrail(bc, ctx, 
        contentPolicyConfig={
            "filtersConfig": [
                {
                    "type": "VIOLENCE",
                    "inputStrength": "HIGH",
                    "outputStrength": "HIGH",
                }
            ]
        })
    gid = create_resp["guardrailId"]
    # Create a version to use
    ver_resp = bc.create_guardrail_version(guardrailIdentifier=gid)
    version = ver_resp["version"]

    # A guardrail (and each created version) provisions asynchronously on real AWS
    # (CREATING -> READY); ApplyGuardrail rejects a guardrail still in CREATING with
    # a ValidationException. An emulator may return READY synchronously, so poll to READY here
    # before applying rather than assuming the synchronous terminal state.
    _poll_until(
        probe=lambda: bc.get_guardrail(
            guardrailIdentifier=gid, guardrailVersion=version
        ).get("status"),
        predicate=lambda s: s == "READY",
        timeout_s=60,
        interval_s=2.0,
        description=f"guardrail {gid} v{version} READY")

    try:
        resp = rt.apply_guardrail(
            guardrailIdentifier=gid,
            guardrailVersion=version,
            source="INPUT",
            content=[{"text": {"text": "Hello, how are you?"}}])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "AccessDeniedException":
            raise AssertionError("No permission to call ApplyGuardrail") from exc
        raise

    assert "usage" in resp, f"ApplyGuardrail response missing 'usage'. Keys: {list(resp.keys())}"
    assert "action" in resp, f"ApplyGuardrail response missing 'action'. Keys: {list(resp.keys())}"
    # "action in (NONE, GUARDRAIL_INTERVENED)" is the entire modeled GuardrailAction enum, so it
    # cannot fail regardless of target behavior. The guardrail here has only a VIOLENCE content
    # filter armed and the probe text matches none of it, so real AWS must report NONE -- pin the
    # specific value the input earns, not the full enum.
    assert resp["action"] == "NONE", (
        f"benign input must not trigger the VIOLENCE-only guardrail; action={resp['action']!r}"
    )
    assert "outputs" in resp, (
        f"ApplyGuardrail response missing 'outputs'. Keys: {list(resp.keys())}"
    )
    assert "assessments" in resp, (
        f"ApplyGuardrail response missing 'assessments'. Keys: {list(resp.keys())}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
