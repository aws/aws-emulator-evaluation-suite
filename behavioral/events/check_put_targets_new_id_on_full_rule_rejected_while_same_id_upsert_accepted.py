"""put-targets-new-id-on-full-rule-rejected-while-same-id-upsert-accepted."""
from __future__ import annotations

import json

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-new-id-on-full-rule-rejected-while-same-id-upsert-accepted"
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


def _targets(ev, rule: str) -> dict:
    return {t["Id"]: t for t in ev.list_targets_by_rule(Rule=rule)["Targets"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """At five targets, PutTargets adding a sixth Id is refused with LimitExceededException leaving
    the same five, an existing-Id upsert is accepted, and a batch mixing both is refused whole.
    """
    ev = ctx.client("events")
    # botocore retries LimitExceededException as a throttle; the refusals are asserted on one attempt.
    ev_once = ctx.client("events", config=Config(retries={"total_max_attempts": 1}))
    rule = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(
        Name=rule,
        EventPattern=json.dumps({"source": ["sim2real.cap"]}),
        State="DISABLED",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))

    arn = _queue_arn(ev, ctx, ctx.unique_name("cap-"))
    ids = [f"t{i}" for i in range(5)]
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=ids + ["t9"]))
    first = ev.put_targets(Rule=rule, Targets=[{"Id": tid, "Arn": arn} for tid in ids])
    assert first["FailedEntryCount"] == 0, f"five targets on an empty rule were refused: {first!r}"
    assert sorted(_targets(ev, rule)) == ids, f"rule holds {sorted(_targets(ev, rule))!r}, expected {ids!r}"

    code, message = _error(lambda: ev_once.put_targets(Rule=rule, Targets=[{"Id": "t9", "Arn": arn}]))
    assert code == "LimitExceededException", f"a sixth distinct Id on a full rule gave {code!r}"
    assert message == "The requested resource exceeds the maximum number allowed.", (
        f"a sixth distinct Id on a full rule was refused with message {message!r}"
    )
    after_refusal = _targets(ev, rule)
    assert sorted(after_refusal) == ids, (
        f"after the refused sixth target the rule holds {sorted(after_refusal)!r}, expected {ids!r}"
    )

    upsert = ev.put_targets(Rule=rule, Targets=[{"Id": "t0", "Arn": arn, "Input": json.dumps({"v": 1})}])
    assert upsert["FailedEntryCount"] == 0, f"re-sending existing Id t0 at the cap was refused: {upsert!r}"
    after_upsert = _targets(ev, rule)
    assert sorted(after_upsert) == ids, (
        f"the upsert of t0 changed the Id set to {sorted(after_upsert)!r}, expected {ids!r}"
    )
    assert json.loads(after_upsert["t0"].get("Input", "null")) == {"v": 1}, (
        f"the upsert of t0 left Input {after_upsert['t0'].get('Input')!r}, expected {{'v': 1}}"
    )

    code, message = _error(lambda: ev_once.put_targets(Rule=rule, Targets=[
        {"Id": "t1", "Arn": arn, "Input": json.dumps({"v": 2})},
        {"Id": "t9", "Arn": arn},
    ]))
    assert code == "LimitExceededException", f"an upsert mixed with a sixth Id gave {code!r}"
    assert message == "The requested resource exceeds the maximum number allowed.", (
        f"an upsert mixed with a sixth Id was refused with message {message!r}"
    )
    after_mixed = _targets(ev, rule)
    assert sorted(after_mixed) == ids, (
        f"after the refused mixed batch the rule holds {sorted(after_mixed)!r}, expected {ids!r}"
    )
    assert "Input" not in after_mixed["t1"], (
        f"the refused mixed batch still applied its upsert: t1 Input is {after_mixed['t1'].get('Input')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
