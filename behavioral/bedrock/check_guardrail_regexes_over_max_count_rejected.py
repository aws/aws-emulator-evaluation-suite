"""guardrail-regexes-over-max-count-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardrail-regexes-over-max-count-rejected"
GROUP = 'guardrails'
SERVICES = ['bedrock']


# ===== helpers =====

_BLOCKED_IN = "sim2real-blocked-input-b512"
_BLOCKED_OUT = "sim2real-blocked-output-b512"
_READY_TIMEOUT_S = 180

# com.amazonaws.bedrock#GuardrailRegexesConfig carries smithy.api#length {min: 1, max: 10}.
# botocore.validate.VALIDATED_METADATA_ATTRS == {'required','min','document','union'} -- `max` is
# NOT validated client-side, so an over-length list is serialised and genuinely reaches the server.
#
# On AWS the modelled bound is NOT the enforced one:
#   11 regexesConfig entries -> ACCEPTED, guardrail reaches READY, GetGuardrail returns all 11
#   30 entries               -> ACCEPTED, READY, all 30 returned
#   31, 50, 100 entries      -> ValidationException
#                               'Number of regexes in sensitive information policy exceeds quota limit.'
# So the service enforces a bound of 30, three times the modelled max of 10.
# Both facts are asserted below, because an emulator that generates its validation from the
# Smithy model will refuse 11 (too strict, breaks a caller whose config AWS accepts) while one
# that stores collections unbounded will accept 31 (too permissive, hides a caller bug until
# production).
_MODELLED_MAX_REGEXES = 10
_MAX_REGEXES = 30
_OVER_QUOTA_MESSAGE = "Number of regexes in sensitive information policy exceeds quota limit."


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


def _list_guardrail_names(bc):
    """Every guardrail name visible to the caller, following nextToken to the terminal page."""
    names, token = [], None
    while True:
        kw = {"maxResults": 100}
        if token:
            kw["nextToken"] = token
        page = bc.list_guardrails(**kw)
        names.extend(g.get("name") for g in page.get("guardrails") or [])
        token = page.get("nextToken")
        if not token:
            return names


def _regexes(count):
    """`count` individually valid, distinctly named regex filters."""
    return [
        {
            "name": f"sim2real-code-{i:03d}",
            "description": f"internal code family {i:03d}",
            "pattern": rf"C{i:03d}-[0-9]{{4}}",
            "action": "BLOCK",
        }
        for i in range(count)
    ]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGuardrail enforces a regex-filter cardinality of 30, above the modelled max of 10: 31 is
    refused with ValidationException and creates nothing, while 11 and 30 are accepted and round-trip
    every entry, so both model-strict and unbounded implementations fail.
    """
    bc = ctx.client("bedrock")

    over = _regexes(_MAX_REGEXES + 1)
    assert len(over) == 31, f"expected 31 regex configs; got {len(over)}"

    # --- break exactly one thing: the number of regex filters ---
    over_name = ctx.unique_name("sim2real-behav-gr-over-")
    try:
        bad = bc.create_guardrail(
            name=over_name,
            description="sim2real regexes over max",
            blockedInputMessaging=_BLOCKED_IN,
            blockedOutputsMessaging=_BLOCKED_OUT,
            sensitiveInformationPolicyConfig={"regexesConfig": over},
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ValidationException", (
            f"{len(over)} regex filters exceeds the enforced maximum of {_MAX_REGEXES} and must be "
            f"rejected with ValidationException; got {code!r} / {message!r}"
        )
        # The message names the *quota* that was breached. Pinning it is what stops an emulator
        # passing this by refusing the request for some unrelated reason -- a rejected pattern, a
        # duplicate name -- while having no cardinality limit at all.
        assert message == _OVER_QUOTA_MESSAGE, (
            f"the refusal must be exactly {_OVER_QUOTA_MESSAGE!r}, naming the regex-count quota so "
            f"the caller can tell it apart from a malformed individual filter; got {message!r}"
        )
    else:
        # Register cleanup FIRST so a wrongly-accepted guardrail is never leaked, then fail.
        ctx.on_cleanup(
            lambda: bc.delete_guardrail(guardrailIdentifier=bad["guardrailId"])
        )
        raise AssertionError(
            f"CreateGuardrail accepted {len(over)} regex filters (enforced max {_MAX_REGEXES}) "
            f"and returned guardrailId={bad['guardrailId']!r}: the collection limit is not enforced"
        )

    # --- effect absent ---
    assert over_name not in _list_guardrail_names(bc), (
        f"a rejected CreateGuardrail must not create the guardrail, but {over_name!r} appears in "
        f"ListGuardrails"
    )

    # --- the modelled bound is not the enforced one: one past `max: 10` is ACCEPTED ---
    past_modelled = _regexes(_MODELLED_MAX_REGEXES + 1)
    lenient_name = ctx.unique_name("sim2real-behav-gr-lenient-")
    lenient = _create_guardrail(
        bc,
        ctx,
        name=lenient_name,
        description="sim2real regexes past modelled max",
        sensitiveInformationPolicyConfig={"regexesConfig": past_modelled},
    )
    _wait_ready(bc, lenient["guardrailId"])
    lenient_stored = (
        (bc.get_guardrail(guardrailIdentifier=lenient["guardrailId"]).get(
            "sensitiveInformationPolicy") or {}).get("regexes") or []
    )
    assert len(lenient_stored) == len(past_modelled), (
        f"{len(past_modelled)} regex filters is past the modelled max of {_MODELLED_MAX_REGEXES} "
        f"but real AWS accepts it and stores every one; got {len(lenient_stored)}. An emulator that "
        f"validates straight from the Smithy model refuses this request and is too strict."
    )

    # --- control: exactly at the enforced limit is accepted, and all 30 are stored ---
    at_limit = _regexes(_MAX_REGEXES)
    name = ctx.unique_name("sim2real-behav-gr-atmax-")
    created = _create_guardrail(
        bc,
        ctx,
        name=name,
        description="sim2real regexes at max",
        sensitiveInformationPolicyConfig={"regexesConfig": at_limit},
    )
    gid = created["guardrailId"]
    _wait_ready(bc, gid)

    stored = bc.get_guardrail(guardrailIdentifier=gid)
    regexes = (stored.get("sensitiveInformationPolicy") or {}).get("regexes") or []
    assert len(regexes) == _MAX_REGEXES, (
        f"a guardrail created with exactly {_MAX_REGEXES} regexes must return {_MAX_REGEXES}; "
        f"got {len(regexes)}"
    )
    assert sorted(r.get("name") for r in regexes) == sorted(r["name"] for r in at_limit), (
        f"GetGuardrail must round-trip every configured regex name; got "
        f"{sorted(r.get('name') for r in regexes)!r}"
    )
    listed = _list_guardrail_names(bc)
    assert name in listed, (
        f"the accepted guardrail {name!r} must appear in ListGuardrails, proving the earlier "
        f"absence was the rejection and not a broken listing"
    )
    assert lenient_name in listed, (
        f"the past-modelled-max guardrail {lenient_name!r} must also be listed; got {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
