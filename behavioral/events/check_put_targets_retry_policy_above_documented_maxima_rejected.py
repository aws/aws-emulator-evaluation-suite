"""put-targets-retry-policy-above-documented-maxima-rejected."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Lower bounds (-1, 59) are not probed: botocore validates integer `min` client-side, so the
# request never reaches the service. botocore does not validate `max`, so upper bounds do.

CHECK = "put-targets-retry-policy-above-documented-maxima-rejected"
GROUP = "targets"
SERVICES = ["events"]

_MAX_RETRY_ATTEMPTS = 185
_MAX_EVENT_AGE_SECONDS = 86400
_TARGET_ID = "t1"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A RetryPolicy at the documented maxima (185 attempts, 86400 s) is stored verbatim; one
    over is refused with ValidationException and leaves the stored policy unchanged.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RetryPolicy.html
    """
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    queue_arn = f"arn:aws:sqs:{ctx.region}:{account}:{ctx.unique_name('sim2real-behav-q-')}"

    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=_tags_kv())
    ctx.on_cleanup(lambda n=bus: _delete_bus_quietly(ctx, n))

    rule = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(
        Name=rule,
        EventBusName=bus,
        EventPattern=json.dumps({"source": ["sim2real.retry-bounds"]}),
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_rule_quietly(ctx, rule, bus))

    at_maximum = {
        "MaximumRetryAttempts": _MAX_RETRY_ATTEMPTS,
        "MaximumEventAgeInSeconds": _MAX_EVENT_AGE_SECONDS,
    }
    accepted = events.put_targets(
        Rule=rule,
        EventBusName=bus,
        Targets=[{"Id": _TARGET_ID, "Arn": queue_arn, "RetryPolicy": dict(at_maximum)}],
    )
    ctx.on_cleanup(lambda: _remove_targets_quietly(ctx, rule, bus))
    assert accepted.get("FailedEntryCount") == 0, (
        f"positive control failed: PutTargets with the documented maxima {at_maximum} must be "
        f"accepted, got FailedEntryCount={accepted.get('FailedEntryCount')!r} "
        f"FailedEntries={accepted.get('FailedEntries')!r}"
    )
    stored = _stored_retry_policy(events, rule, bus)
    assert stored == at_maximum, (
        f"the accepted RetryPolicy must round-trip byte-identical through ListTargetsByRule: "
        f"expected {at_maximum}, got {stored!r} — a target that clamps or rewrites the value is "
        f"silently changing delivery behaviour"
    )

    probe_a = _refuse_put_targets(
        events,
        rule,
        bus,
        {
            "Id": _TARGET_ID,
            "Arn": queue_arn,
            "RetryPolicy": {
                "MaximumRetryAttempts": _MAX_RETRY_ATTEMPTS + 1,
                "MaximumEventAgeInSeconds": _MAX_EVENT_AGE_SECONDS,
            },
        },
        label=f"MaximumRetryAttempts={_MAX_RETRY_ATTEMPTS + 1}",
    )
    unchanged_a = _stored_retry_policy(events, rule, bus)
    assert unchanged_a == at_maximum, (
        f"the refused PutTargets must not have partially written: expected the stored policy to "
        f"still be {at_maximum}, ListTargetsByRule now reports {unchanged_a!r}"
    )

    probe_b = _refuse_put_targets(
        events,
        rule,
        bus,
        {
            "Id": _TARGET_ID,
            "Arn": queue_arn,
            "RetryPolicy": {
                "MaximumRetryAttempts": _MAX_RETRY_ATTEMPTS,
                "MaximumEventAgeInSeconds": _MAX_EVENT_AGE_SECONDS + 1,
            },
        },
        label=f"MaximumEventAgeInSeconds={_MAX_EVENT_AGE_SECONDS + 1}",
    )
    unchanged_b = _stored_retry_policy(events, rule, bus)
    assert unchanged_b == at_maximum, (
        f"the refused PutTargets must not have partially written: expected the stored policy to "
        f"still be {at_maximum}, ListTargetsByRule now reports {unchanged_b!r}"
    )

    # Each ValidationException message names its own field and value; only that member name is
    # left unpinned, as the service spells it in its own casing.
    surface_a, code_a, message_a = probe_a
    surface_b, code_b, message_b = probe_b
    assert (surface_a, code_a) == (surface_b, code_b), (
        f"the two out-of-range RetryPolicy probes must be refused with the same surface and code: "
        f"MaximumRetryAttempts probe gave surface={surface_a!r} code={code_a!r}, "
        f"MaximumEventAgeInSeconds probe gave surface={surface_b!r} code={code_b!r} — a target that "
        f"refuses one and something else for the other is not applying a single range check"
    )
    assert code_a == "ValidationException", (
        f"an out-of-range RetryPolicy must be refused with ValidationException; got "
        f"surface={surface_a!r} code={code_a!r} message={message_a!r}"
    )
    for message, value, limit in (
        (message_a, _MAX_RETRY_ATTEMPTS + 1, _MAX_RETRY_ATTEMPTS),
        (message_b, _MAX_EVENT_AGE_SECONDS + 1, _MAX_EVENT_AGE_SECONDS),
    ):
        head = f"1 validation error detected: Value '{value}' at 'targets.1.member.retryPolicy."
        tail = f"' failed to satisfy constraint: Member must have value less than or equal to {limit}"
        assert message.startswith(head) and message.endswith(tail), (
            f"expected a message starting {head!r} and ending {tail!r}, got {message!r}"
        )

    # The refused calls must leave the rule usable rather than wedged.
    requalified = events.put_targets(
        Rule=rule,
        EventBusName=bus,
        Targets=[
            {
                "Id": _TARGET_ID,
                "Arn": queue_arn,
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            }
        ],
    )
    assert requalified.get("FailedEntryCount") == 0, (
        f"after two refusals a legal PutTargets must still succeed on the same rule, got "
        f"FailedEntryCount={requalified.get('FailedEntryCount')!r} "
        f"FailedEntries={requalified.get('FailedEntries')!r}"
    )
    final = _stored_retry_policy(events, rule, bus)
    assert final == {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}, (
        f"the overwrite must replace the stored policy: expected the documented minima, got {final!r}"
    )


_MANAGED_TAG_KEY = "sim2real:managed"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _stored_retry_policy(events, rule: str, bus: str) -> dict:
    """The RetryPolicy of target _TARGET_ID, read through ListTargetsByRule."""
    targets = events.list_targets_by_rule(Rule=rule, EventBusName=bus).get("Targets", [])
    matching = [t for t in targets if t["Id"] == _TARGET_ID]
    assert len(matching) == 1, (
        f"ListTargetsByRule({rule}) must report exactly one target with Id={_TARGET_ID!r}, got "
        f"{[t.get('Id') for t in targets]}"
    )
    return matching[0]["RetryPolicy"]


def _refuse_put_targets(events, rule: str, bus: str, target: dict, *, label: str):
    """Call PutTargets expecting a refusal and raise if it was accepted.

    Returns ("exception"|"entry", code, message).
    """
    try:
        resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=[target])
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return ("exception", err.get("Code"), err.get("Message") or "")
    failed = resp.get("FailedEntries") or []
    if resp.get("FailedEntryCount"):
        assert len(failed) == resp["FailedEntryCount"], (
            f"FailedEntryCount={resp['FailedEntryCount']} but FailedEntries has {len(failed)} rows: "
            f"{failed!r}"
        )
        return ("entry", failed[0].get("ErrorCode"), failed[0].get("ErrorMessage") or "")
    raise AssertionError(
        f"PutTargets ACCEPTED an out-of-range RetryPolicy ({label}) — real EventBridge documents "
        f"MaximumRetryAttempts 0..{_MAX_RETRY_ATTEMPTS} and MaximumEventAgeInSeconds "
        f"60..{_MAX_EVENT_AGE_SECONDS}. Response was {resp!r}"
    )


def _remove_targets_quietly(ctx, rule: str, bus: str) -> None:
    _ignore_not_found(
        lambda: ctx.client("events").remove_targets(Rule=rule, EventBusName=bus, Ids=[_TARGET_ID]),
        f"remove target {_TARGET_ID} from rule {rule}",
    )


def _delete_rule_quietly(ctx, rule: str, bus: str) -> None:
    _ignore_not_found(
        lambda: ctx.client("events").delete_rule(Name=rule, EventBusName=bus, Force=True),
        f"delete rule {rule}",
    )


def _delete_bus_quietly(ctx, name: str) -> None:
    _ignore_not_found(
        lambda: ctx.client("events").delete_event_bus(Name=name), f"delete event bus {name}"
    )


def _ignore_not_found(fn, what: str) -> None:
    """Run a teardown call; only ResourceNotFoundException (already gone) is tolerated."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise RuntimeError(f"could not {what}: {code}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
