"""put-targets-duplicate-id-in-one-request-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-duplicate-id-in-one-request-rejected"
GROUP = 'targets'
SERVICES = ['events']


def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _queue_arn(ev, ctx, suffix: str) -> str:
    """A syntactically valid SQS queue ARN in this account and region (EventBridge does not
    require a target to exist at PutTargets time)."""
    partition = ev.describe_event_bus(Name="default")["Arn"].split(":")[1]
    return f"arn:{partition}:sqs:{ctx.region}:{ctx.account}:sim2real-behav-{suffix}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One PutTargets request naming the same target Id twice is refused whole with
    ValidationException naming the Id, leaving the existing target untouched; the same entries under
    distinct Ids are then accepted.
    """
    ev = ctx.client("events")
    rule = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(
        Name=rule,
        EventPattern=json.dumps({"source": ["sim2real.dup"]}),
        State="DISABLED",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))

    arn_a = _queue_arn(ev, ctx, ctx.unique_name("dup-a-"))
    arn_b = _queue_arn(ev, ctx, ctx.unique_name("dup-b-"))
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["keep", "dup", "dup-2"]))
    ev.put_targets(Rule=rule, Targets=[{"Id": "keep", "Arn": arn_a}])

    code, message = _error(lambda: ev.put_targets(Rule=rule, Targets=[
        {"Id": "dup", "Arn": arn_a},
        {"Id": "dup", "Arn": arn_b},
    ]))
    assert code == "ValidationException", f"two entries sharing Id 'dup' gave {code!r}"
    assert message == "Parameter targets is not valid. Reason: More than one target with Id 'dup' is provided.", (
        f"two entries sharing Id 'dup' were refused with message {message!r}"
    )
    after = {t["Id"]: t["Arn"] for t in ev.list_targets_by_rule(Rule=rule)["Targets"]}
    assert after == {"keep": arn_a}, (
        f"after the refused duplicate-Id request the rule holds {sorted(after)!r}, expected only 'keep'"
    )

    ok = ev.put_targets(Rule=rule, Targets=[{"Id": "dup", "Arn": arn_a}, {"Id": "dup-2", "Arn": arn_b}])
    assert ok["FailedEntryCount"] == 0, f"the same entries under distinct Ids were refused: {ok!r}"
    final = {t["Id"]: t["Arn"] for t in ev.list_targets_by_rule(Rule=rule)["Targets"]}
    assert final == {"keep": arn_a, "dup": arn_a, "dup-2": arn_b}, (
        f"after the distinct-Id request the rule holds Ids {sorted(final)!r}, expected keep, dup, dup-2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
