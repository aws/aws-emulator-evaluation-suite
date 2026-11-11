"""apply-guardrail-denied-topic-named-in-assessment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-guardrail-denied-topic-named-in-assessment"
GROUP = 'guardrail_enforcement'
SERVICES = ['bedrock']


_BLOCKED_IN = "sim2real-blocked-input-2b60"
_BLOCKED_OUT = "sim2real-blocked-output-2b60"
_READY_TIMEOUT_S = 180

_TOPIC_NAME = "sim2real-crypto-investment-advice"
_TOPIC_DEF = (
    "Requests for advice on which cryptocurrency to buy, sell or hold as an investment, "
    "including price predictions and portfolio allocation."
)


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


def _topics(resp, **fields):
    """assessments[0].topicPolicy.topics entries matching every field."""
    assessments = resp["assessments"]
    assert assessments, f"ApplyGuardrail.assessments must be non-empty; got {assessments!r}"
    entries = (assessments[0].get("topicPolicy") or {}).get("topics") or []
    return [e for e in entries if all(e.get(k) == v for k, v in fields.items())]


@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DENY topic guardrail round-trips its topic, blocks on-topic input with an assessment naming
    that topic (type DENY, action BLOCKED) and the blocked messaging, and lets off-topic input pass
    on the same version.
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")

    created = _create_guardrail(
        bc,
        ctx,
        description="sim2real denied topic policy",
        tags=[{"key": "sim2real", "value": CHECK}],
        topicPolicyConfig={
            "topicsConfig": [
                {
                    "name": _TOPIC_NAME,
                    "definition": _TOPIC_DEF,
                    "examples": [
                        "Should I buy bitcoin right now?",
                        "Which altcoin will double this year?",
                    ],
                    "type": "DENY",
                }
            ]
        },
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)

    stored = bc.get_guardrail(guardrailIdentifier=gid)
    topics = (stored.get("topicPolicy") or {}).get("topics") or []
    assert [t.get("name") for t in topics] == [_TOPIC_NAME], (
        f"GetGuardrail.topicPolicy.topics must round-trip exactly [{_TOPIC_NAME!r}]; got {topics!r}"
    )
    assert topics[0].get("definition") == _TOPIC_DEF, (
        f"topic definition must round-trip verbatim; got {topics[0].get('definition')!r}"
    )

    version = _publish_version(bc, ctx, gid)

    resp = _apply(rt, gid, version, "Should I buy ethereum as an investment this month?")
    assert resp["action"] == "GUARDRAIL_INTERVENED", (
        f"on-topic input must be blocked by the DENY topic; action={resp['action']!r} "
        f"assessments={resp['assessments']!r}"
    )
    hits = _topics(resp, name=_TOPIC_NAME, type="DENY", action="BLOCKED")
    assert hits, (
        f"no topicPolicy.topics entry with name={_TOPIC_NAME!r} type=DENY action=BLOCKED; "
        f"assessments[0]={resp['assessments'][0]!r}"
    )
    texts = [o.get("text") for o in resp["outputs"]]
    assert _BLOCKED_IN in " ".join(t for t in texts if t), (
        f"a topic block must return the configured blockedInputMessaging {_BLOCKED_IN!r}; "
        f"got {texts!r}"
    )

    # Control: clearly off-topic input through the SAME version must pass, so a guardrail that
    # blocks every request fails here.
    control = _apply(rt, gid, version, "What time does the library close on Sunday?")
    assert control["action"] == "NONE", (
        f"off-topic input must not intervene; action={control['action']!r} "
        f"assessments={control['assessments']!r}"
    )
    assert not _topics(control, action="BLOCKED"), (
        f"off-topic input produced a BLOCKED topic assessment: {control['assessments']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
