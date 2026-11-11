"""sm-version-publish-list-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sm-version-publish-list-delete"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Publishing a version adds it to ListStateMachineVersions; deleting it
    removes it from that list."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DEF_V1)
    sfn = ctx.client("stepfunctions")

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_DEF_V2))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    versions = _list_versions(sfn, sm_arn)
    assert v1_arn in versions, versions
    assert v2_arn in versions, versions

    sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn)

    # DeleteStateMachineVersion is asynchronous: the version can linger in
    # ListStateMachineVersions briefly after the delete call returns, so poll
    # for it to disappear instead of asserting immediately.
    versions_after = _poll_until(
        lambda: _list_versions(sfn, sm_arn),
        lambda vs: v1_arn not in vs,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert v1_arn not in versions_after, f"v1 still listed after delete: {versions_after}"
    assert v2_arn in versions_after, f"v2 disappeared unexpectedly: {versions_after}"

    # The deleted version is gone, not just unlisted: an independent describe
    # on its own ARN must resolve to the specific not-found code (the same
    # eventual-consistency window applies), and a mutation against the dead
    # id must fail with that same code rather than silently working.
    from botocore.exceptions import ClientError

    def _describe_v1_error():
        try:
            sfn.describe_state_machine(stateMachineArn=v1_arn)
            return None
        except ClientError as exc:
            return exc.response["Error"]

    describe_error = _poll_until(
        _describe_v1_error,
        lambda e: e is not None,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert describe_error.get("Code") == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist describing deleted version, got {describe_error!r}"
    )
    expected_describe = f"State Machine Version Does Not Exist: '{v1_arn}'"
    assert describe_error.get("Message") == expected_describe, (
        f"expected {expected_describe!r}, got {describe_error.get('Message')!r}"
    )

    try:
        sfn.start_execution(stateMachineArn=v1_arn, input="{}")
        raise AssertionError("StartExecution on a deleted version unexpectedly succeeded")
    except ClientError as exc:
        start_error = exc.response["Error"]
    assert start_error.get("Code") == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist starting an execution on a deleted version, got {start_error!r}"
    )
    expected_start = f"State Machine Version Does Not Exist: '{v1_arn}'"
    assert start_error.get("Message") == expected_start, (
        f"expected {expected_start!r}, got {start_error.get('Message')!r}"
    )

    # v2 remains fully usable throughout.
    sfn.describe_state_machine(stateMachineArn=v2_arn)


def _list_versions(sfn, sm_arn):
    out = []
    next_token = None
    while True:
        kwargs = {"stateMachineArn": sm_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        page = sfn.list_state_machine_versions(**kwargs)
        out.extend(v["stateMachineVersionArn"] for v in page["stateMachineVersions"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return out


_DEF_V1 = {
    "Comment": "v1",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "v1", "End": True}},
}
_DEF_V2 = {
    "Comment": "v2",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "v2", "End": True}},
}

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD"):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sfn-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real-check", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
