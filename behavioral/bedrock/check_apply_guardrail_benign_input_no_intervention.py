"""apply-guardrail-benign-input-no-intervention."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-benign-input-no-intervention"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock']


_BLOCKED_IN = "sim2real-blocked-input-6e05"
_BLOCKED_OUT = "sim2real-blocked-output-6e05"
_READY_TIMEOUT_S = 180

_TOPIC_NAME = "sim2real-competitor-pricing"
_REGEX_NAME = "sim2real-ticket-id"
_WORD = "zorblatt"

# Every policy branch of GuardrailAssessment that this guardrail configures, and the assessment
# verbs that mean "this branch fired".
_FIRED = ("BLOCKED", "ANONYMIZED")

# Deliberately anodyne: no profanity, no PII, no named entity, no imperative, no question about a
# competitor, nothing resembling a prompt injection.
_BENIGN = "The community library opens at nine in the morning on weekdays."


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
    kwargs.setdefault("tags", [{"key": "sim2real", "value": CHECK}])
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


def _actions(assessment):
    """Every `action` verb reported anywhere in one GuardrailAssessment, as (path, verb) pairs."""
    out = []
    sip = assessment.get("sensitiveInformationPolicy") or {}
    for key in ("piiEntities", "regexes"):
        for entry in sip.get(key) or []:
            out.append((f"sensitiveInformationPolicy.{key}", entry.get("action")))
    wp = assessment.get("wordPolicy") or {}
    for key in ("customWords", "managedWordLists"):
        for entry in wp.get(key) or []:
            out.append((f"wordPolicy.{key}", entry.get("action")))
    for entry in (assessment.get("topicPolicy") or {}).get("topics") or []:
        out.append(("topicPolicy.topics", entry.get("action")))
    for entry in (assessment.get("contentPolicy") or {}).get("filters") or []:
        out.append(("contentPolicy.filters", entry.get("action")))
    return out


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A guardrail with every text policy type configured aggressively returns action NONE for
    anodyne input, with no sub-policy reporting a detection and no blocked messaging, while its
    custom word on the same version still intervenes: it does not over-block.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = _create_guardrail(
        bc,
        ctx,
        description="sim2real all-policies-on over-blocking control",
        # Aggressive on every axis: HIGH content filters, a denied topic, a custom word, a PII
        # entity, and a custom regex. None of them should match _BENIGN.
        contentPolicyConfig={
            "filtersConfig": [
                {"type": t, "inputStrength": "HIGH", "outputStrength": "HIGH"}
                for t in ("HATE", "INSULTS", "SEXUAL", "VIOLENCE", "MISCONDUCT")
            ]
        },
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": _TOPIC_NAME,
                    "definition": (
                        "Questions about how a competitor prices its products, or requests to "
                        "compare our prices against a named competitor."
                    ),
                    "examples": ["How much cheaper is the competing product?"],
                    "type": "DENY",
                }
            ]
        },
        wordPolicyConfig={"wordsConfig": [{"text": _WORD}]},
        sensitiveInformationPolicyConfig={
            "piiEntitiesConfig": [{"type": "US_SOCIAL_SECURITY_NUMBER", "action": "BLOCK"}],
            "regexesConfig": [
                {
                    "name": _REGEX_NAME,
                    "description": "internal ticket id",
                    "pattern": r"TKT-[0-9]{5}",
                    "action": "BLOCK",
                }
            ],
        },
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)
    version = _publish_version(bc, ctx, gid)

    resp = _apply(rt, gid, version, _BENIGN)

    assert resp["action"] == "NONE", (
        f"benign input must pass a fully-configured guardrail untouched; "
        f"action={resp['action']!r} assessments={resp.get('assessments')!r}"
    )

    # No sub-policy may report a detection. An empty/absent assessments list is fine -- what is
    # NOT fine is any BLOCKED/ANONYMIZED verb anywhere in it.
    fired = [
        (path, verb)
        for assessment in (resp.get("assessments") or [])
        for path, verb in _actions(assessment)
        if verb in _FIRED
    ]
    assert not fired, (
        f"benign input produced detections {fired!r}; assessments={resp['assessments']!r}"
    )

    # The refusal strings must not appear on a pass.
    texts = [o.get("text") for o in resp.get("outputs") or []]
    joined = " ".join(t for t in texts if t)
    assert _BLOCKED_IN not in joined and _BLOCKED_OUT not in joined, (
        f"a non-intervened response must not carry the blocked messaging; outputs={texts!r}"
    )

    # Positive control on the SAME version: the guardrail is genuinely armed, so this check cannot
    # pass on an emulator that simply never enforces anything. The custom word is a deterministic,
    # operator-specified trigger (no AWS classifier involved).
    armed = _apply(rt, gid, version, f"The {_WORD} is on the shelf.")
    assert armed["action"] == "GUARDRAIL_INTERVENED", (
        f"positive control: the configured custom word {_WORD!r} must still intervene, otherwise "
        f"the NONE above proves nothing; action={armed['action']!r} "
        f"assessments={armed.get('assessments')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
