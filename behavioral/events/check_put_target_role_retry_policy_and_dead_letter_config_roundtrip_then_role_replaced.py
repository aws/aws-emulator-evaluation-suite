"""put-target-role-retry-policy-and-dead-letter-config-roundtrip-then-role-replaced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# RoleArn is supplied on every PutTargets call: a Step Functions target that omits it is rejected.

CHECK = "put-target-role-retry-policy-and-dead-letter-config-roundtrip-then-role-replaced"
GROUP = "targets"
SERVICES = ["events"]

_RETRY_POLICY = {"MaximumRetryAttempts": 2, "MaximumEventAgeInSeconds": 60}


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Step Functions target's RoleArn, RetryPolicy and DeadLetterConfig read back as written, and
    a later PutTargets on the same Id with a new RoleArn replaces the role in place, leaving one
    target and the RetryPolicy and DeadLetterConfig unchanged.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_1_arn = _create_events_role(ctx, iam, ctx.unique_name("sim2real-behav-role1-"))
    role_2_arn = _create_events_role(ctx, iam, ctx.unique_name("sim2real-behav-role2-"))

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    pattern = json.dumps({"source": [ctx.unique_name("sim2real.roletrip.")]})
    events.put_rule(Name=rule_name, EventPattern=pattern)
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    ctx.on_cleanup(lambda: _remove_targets_quietly(events, rule_name))

    sm_arn = f"arn:aws:states:{ctx.region}:{account}:stateMachine:{ctx.unique_name('sim2real-behav-sm-')}"

    _put_targets_with_retry(ctx, events, rule_name, {
        "Id": "t1",
        "Arn": sm_arn,
        "RoleArn": role_1_arn,
        "RetryPolicy": _RETRY_POLICY,
        "DeadLetterConfig": {"Arn": dlq_arn},
    })
    first = _only_target(events, rule_name)
    assert first["RoleArn"] == role_1_arn, f"expected RoleArn {role_1_arn!r}, got {first['RoleArn']!r}"
    assert first["RetryPolicy"] == _RETRY_POLICY, f"expected RetryPolicy {_RETRY_POLICY!r}, got {first['RetryPolicy']!r}"
    assert first["DeadLetterConfig"] == {"Arn": dlq_arn}, (
        f"expected DeadLetterConfig arn {dlq_arn!r}, got {first['DeadLetterConfig']!r}"
    )

    _put_targets_with_retry(ctx, events, rule_name, {
        "Id": "t1",
        "Arn": sm_arn,
        "RoleArn": role_2_arn,
        "RetryPolicy": _RETRY_POLICY,
        "DeadLetterConfig": {"Arn": dlq_arn},
    })
    targets_after = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert len(targets_after) == 1, f"expected exactly one target after the replace, got {targets_after!r}"
    second = targets_after[0]
    assert second["RoleArn"] == role_2_arn, f"expected the REPLACED RoleArn {role_2_arn!r}, got {second['RoleArn']!r}"
    assert second["RoleArn"] != first["RoleArn"], "the role must actually have changed between the two calls"
    assert second["RetryPolicy"] == _RETRY_POLICY, (
        f"RetryPolicy must survive the role replace unchanged; got {second['RetryPolicy']!r}"
    )
    assert second["DeadLetterConfig"] == {"Arn": dlq_arn}, (
        f"DeadLetterConfig must survive the role replace unchanged; got {second['DeadLetterConfig']!r}"
    )



_TRUST_EVENTS = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sts:AssumeRole"}],
})


def _create_events_role(ctx, iam, role_name: str) -> str:
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_EVENTS)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _put_targets_with_retry(ctx, events, rule: str, target: dict, *, timeout_s: float = 80.0) -> None:
    """IAM role propagation has no condition to poll, so retry, bounded, on the specific
    'cannot be assumed' error."""
    last: Exception | None = None
    deadline = time.monotonic() + timeout_s
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while time.monotonic() < deadline:
        try:
            resp = events.put_targets(Rule=rule, Targets=[target])
            assert resp["FailedEntryCount"] == 0, f"PutTargets failed entries: {resp.get('FailedEntries')!r}"
            return
        except ClientError as exc:
            if "cannot be assumed" not in str(exc):
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"PutTargets never accepted the role within {timeout_s}s: {last}")


def _only_target(events, rule: str) -> dict:
    targets = events.list_targets_by_rule(Rule=rule)["Targets"]
    assert len(targets) == 1, f"expected exactly one target on {rule!r}, got {targets!r}"
    return targets[0]


def _remove_targets_quietly(events, rule: str) -> None:
    """DeleteRule rejects a rule that still has targets (``Force`` only waives that check for a
    rule a service created on your behalf, never for one you own) -- remove them first."""
    ids = [t["Id"] for t in events.list_targets_by_rule(Rule=rule).get("Targets", [])]
    if ids:
        events.remove_targets(Rule=rule, Ids=ids)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
