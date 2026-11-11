"""create-state-machine-near-max-definition-round-trips-byte-exact."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-near-max-definition-round-trips-byte-exact"
GROUP = "representation"
SERVICES = ["stepfunctions"]

_TARGET_LEN = 900_000  # characters; comfortably under CreateStateMachine's 1,048,576 maximum

_SFN_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _near_max_definition(target_len: int) -> str:
    """A syntactically valid ASL document whose JSON text is exactly ``target_len`` characters."""
    skeleton = json.dumps(
        {"Comment": "", "StartAt": "Noop", "States": {"Noop": {"Type": "Pass", "End": True}}}
    )
    pad_len = target_len - len(skeleton)
    assert pad_len > 0, f"skeleton alone is {len(skeleton)} chars, already over target {target_len}"
    return json.dumps(
        {
            "Comment": "x" * pad_len,
            "StartAt": "Noop",
            "States": {"Noop": {"Type": "Pass", "End": True}},
        }
    )


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sfn-bigdef-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_SFN_TRUST,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_with_role_propagation(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ~900 KB CreateStateMachine definition, near the 1,048,576-character maximum, round-trips
    byte-exact through DescribeStateMachine, before and after an execution runs to completion.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role(ctx)
    definition = _near_max_definition(_TARGET_LEN)
    assert len(definition) == _TARGET_LEN, len(definition)
    assert len(definition) < 1_048_576, "fixture definition must stay under the real limit"

    name = ctx.unique_name("sim2real-sfn-bigdef-")
    resp = _create_with_role_propagation(
        sfn,
        name=name,
        definition=definition,
        roleArn=role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn)))

    described = sfn.describe_state_machine(stateMachineArn=arn)
    assert described["definition"] == definition, (
        f"DescribeStateMachine returned a {len(described['definition'])}-character definition that "
        f"differs from the {len(definition)}-character one submitted at create"
    )
    assert described["status"] == "ACTIVE", f"expected ACTIVE, got {described['status']!r}"

    exec_arn = sfn.start_execution(stateMachineArn=arn, input="{}")["executionArn"]
    ctx.on_cleanup(
        _teardown(lambda: sfn.stop_execution(executionArn=exec_arn), "ExecutionDoesNotExist")
    )
    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    assert final["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {final['status']!r}: {final.get('error')!r} {final.get('cause')!r}"
    )

    redescribed = sfn.describe_state_machine(stateMachineArn=arn)
    assert redescribed["definition"] == definition, (
        "after an execution ran to completion, DescribeStateMachine no longer returns the "
        "byte-exact original definition"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
