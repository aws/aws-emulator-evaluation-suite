"""apply-guardrail-pii-anonymize-masks-output."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-pii-anonymize-masks-output"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock']


# ===== helpers =====

_BLOCKED_IN = "sim2real blocked input message."
_BLOCKED_OUT = "sim2real blocked output message."
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
    """Converge on the terminal GuardrailStatus (READY or FAILED); ApplyGuardrail rejects a
    guardrail that is not READY."""
    status = _poll(
        lambda: _guardrail_status(bc, gid, version),
        lambda s: s in ("READY", "FAILED"),
        timeout_s=_READY_TIMEOUT_S,
    )
    assert status == "READY", (
        f"guardrail {gid} version={version or 'DRAFT'} never reached READY; "
        f"last status={status!r} (modeled GuardrailStatus: CREATING/UPDATING/VERSIONING/"
        f"READY/FAILED/DELETING)"
    )


def _create_guardrail(bc, ctx, **kwargs):
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-gr-"))
    kwargs.setdefault("blockedInputMessaging", _BLOCKED_IN)
    kwargs.setdefault("blockedOutputsMessaging", _BLOCKED_OUT)
    resp = bc.create_guardrail(**kwargs)
    ctx.on_cleanup(lambda: bc.delete_guardrail(guardrailIdentifier=resp["guardrailId"]))
    return resp


def _publish_version(bc, ctx, gid):
    """CreateGuardrailVersion freezes the DRAFT. Cleanups run LIFO, so registering the version
    delete AFTER the guardrail delete makes the version tear down FIRST."""
    version = bc.create_guardrail_version(guardrailIdentifier=gid)["version"]
    ctx.on_cleanup(
        lambda: bc.delete_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    )
    _wait_ready(bc, gid, version)
    return version


def _apply(rt, gid, version, text, source):
    """ApplyGuardrail runs the guardrail policy engine with NO model involved: no weights, no
    inference. Text is one short sentence -- ApplyGuardrail bills per text unit."""
    try:
        return rt.apply_guardrail(
            guardrailIdentifier=gid,
            guardrailVersion=version,
            source=source,
            content=[{"text": {"text": text}}],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "AccessDeniedException":
            raise AssertionError(
                "ApplyGuardrail -> AccessDeniedException. In this sandbox bedrock has been "
                "reachable only via AWS_BEARER_TOKEN_BEDROCK, not the task-role IAM identity, "
                "so AccessDenied here is an ENVIRONMENT artifact and NOT an emulator fidelity "
                "signal. Re-run with the bearer token present to grade this check."
            ) from exc
        raise


def _pii_entries(resp, **fields):
    """assessments[0].sensitiveInformationPolicy.piiEntities entries matching every field."""
    assessments = resp["assessments"]
    assert assessments, f"ApplyGuardrail.assessments must be non-empty; got {assessments!r}"
    entries = (assessments[0].get("sensitiveInformationPolicy") or {}).get("piiEntities") or []
    return [e for e in entries if all(e.get(k) == v for k, v in fields.items())]


def _si_units(resp):
    """usage.sensitiveInformationPolicyUnits -- 0 when the PII policy did not run at all."""
    return (resp.get("usage") or {}).get("sensitiveInformationPolicyUnits")


# AWS masks an anonymized entity as its type in braces; pinning the token rejects an implementation
# that satisfies "the raw value is gone" by dropping the whole message.
_MASK_TOKEN = "{EMAIL}"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PII ANONYMIZE guardrail masks the entity to `{EMAIL}` (type=EMAIL, action=ANONYMIZED) only for
    source=OUTPUT; for source=INPUT the sensitive-information policy does not run (0 units), so an
    implementation that ignores `source` silently rewrites prompts.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = _create_guardrail(
        bc,
        ctx,
        description="sim2real PII anonymize policy",
        sensitiveInformationPolicyConfig={
            "piiEntitiesConfig": [{"type": "EMAIL", "action": "ANONYMIZE"}]
        },
        tags=[{"key": "sim2real", "value": "guardrail-pii-anonymize"}],
    )
    gid = created["guardrailId"]
    assert created["version"] == "DRAFT", (
        f"CreateGuardrailResponse.version is modeled as GuardrailDraftVersion (^DRAFT$); "
        f"got {created['version']!r}"
    )
    _wait_ready(bc, gid)
    version = _publish_version(bc, ctx, gid)

    secret = "casey.jones@example.com"
    prompt = f"Please email me at {secret} tomorrow."
    resp = _apply(rt, gid, version, prompt, "OUTPUT")

    # 1. The policy fired, and the reason distinguishes masking from blocking. Both GUARDRAIL_INTERVENED
    #    outcomes carry the same `action`, so actionReason is the only field that tells a caller whether
    #    its text was rewritten or refused.
    assert resp["action"] == "GUARDRAIL_INTERVENED", (
        f"an ANONYMIZE hit on the response side is an intervention; "
        f"ApplyGuardrail.action={resp['action']!r} actionReason={resp.get('actionReason')!r}"
    )
    assert resp.get("actionReason") == "Guardrail masked.", (
        f"a masking intervention must be distinguishable from a blocking one by actionReason; "
        f"got {resp.get('actionReason')!r}"
    )

    # 2. The assessment names the SPECIFIC entity type and the assessment-side action verb.
    hits = _pii_entries(resp, type="EMAIL", action="ANONYMIZED")
    assert hits, (
        "no piiEntities entry with type=EMAIL action=ANONYMIZED; "
        f"assessments[0]={resp['assessments'][0]!r}"
    )
    assert hits[0].get("match") == secret, (
        f"GuardrailPiiEntityFilter.match must be the matched text {secret!r}; "
        f"got {hits[0].get('match')!r}"
    )
    assert hits[0].get("detected") is True, (
        f"a matched entity must be reported detected=True; got {hits[0]!r}"
    )
    assert _si_units(resp) == 1, (
        f"a sensitive-information evaluation that matched must bill one policy unit; "
        f"usage={resp.get('usage')!r}"
    )

    # 3. The masked output is the input with the entity replaced by the type token -- exactly, so
    #    that neither a leak nor a wholesale drop of the message can pass.
    texts = [o.get("text") for o in resp["outputs"]]
    assert texts == [prompt.replace(secret, _MASK_TOKEN)], (
        f"ANONYMIZE must substitute {_MASK_TOKEN} for the entity and leave the rest of the text "
        f"byte-identical; got {texts!r}"
    )
    joined = " ".join(t for t in texts if t)
    assert secret not in joined, (
        f"ANONYMIZE leaked the raw entity into outputs: {joined!r}"
    )

    # 4. The source asymmetry: the SAME text and the SAME guardrail version, evaluated as a request
    #    instead of a response, is not masked -- and `units == 0` proves the sensitive-information
    #    policy was never evaluated, rather than evaluated and found nothing.
    as_input = _apply(rt, gid, version, prompt, "INPUT")
    assert as_input["action"] == "NONE", (
        f"an ANONYMIZE-configured entity is a response-side transform: with source=INPUT the same "
        f"text must not intervene; got action={as_input['action']!r} "
        f"actionReason={as_input.get('actionReason')!r}"
    )
    assert as_input["outputs"] == [], (
        f"a non-intervening ApplyGuardrail returns no rewritten output; got {as_input['outputs']!r}"
    )
    assert _si_units(as_input) == 0, (
        f"with source=INPUT the sensitive-information policy must not run at all, so it must bill "
        f"zero units; got usage={as_input.get('usage')!r}"
    )
    assert not _pii_entries(as_input, type="EMAIL"), (
        f"source=INPUT must produce no piiEntities assessment; got {as_input['assessments'][0]!r}"
    )

    # 5. Control: benign text on the SAME source and version must not intervene, so the check
    #    cannot pass on an emulator that masks unconditionally.
    control = _apply(rt, gid, version, "The weather is mild today.", "OUTPUT")
    assert control["action"] == "NONE", (
        f"benign text must not intervene on the same guardrail; action={control['action']!r}, "
        f"assessments={control['assessments']!r}"
    )
    assert control.get("actionReason") == "No action.", (
        f"a non-intervening evaluation must say so; got {control.get('actionReason')!r}"
    )
    assert not _pii_entries(control, action="ANONYMIZED"), (
        f"benign text produced an ANONYMIZED assessment: {control['assessments']!r}"
    )
    # Measured on real AWS: benign text on source=OUTPUT still bills ONE sensitive-information unit.
    # The unit counts the policy being EVALUATED, not the entity being matched -- which is exactly
    # what makes the `units == 0` assertion on source=INPUT above load-bearing: zero there cannot be
    # explained by "nothing matched", it can only mean the policy was never run.
    assert _si_units(control) == 1, (
        f"a sensitive-information policy that runs bills a unit whether or not it matches, so "
        f"benign text on source=OUTPUT must still bill one; usage={control.get('usage')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
