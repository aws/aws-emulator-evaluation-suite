"""delete-state-machine-version-removes-from-list."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-state-machine-version-removes-from-list"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting a specific version removes only that version from the
    version list, leaving the others (published before and after it) intact."""
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DEF_V1)
    sfn = ctx.client("stepfunctions")

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_DEF_V2))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_DEF_V3))
    v3_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]

    versions = _list_versions(sfn, sm_arn)
    assert {v1_arn, v2_arn, v3_arn}.issubset(set(versions)), versions

    sfn.delete_state_machine_version(stateMachineVersionArn=v2_arn)

    # DeleteStateMachineVersion is asynchronous: the version can linger in
    # ListStateMachineVersions briefly after the delete call returns, so poll
    # for it to disappear instead of asserting immediately.
    versions_after = _poll_until(
        lambda: set(_list_versions(sfn, sm_arn)),
        lambda vs: v2_arn not in vs,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert v1_arn in versions_after, f"v1 unexpectedly removed: {versions_after}"
    assert v3_arn in versions_after, f"v3 unexpectedly removed: {versions_after}"
    assert v2_arn not in versions_after, f"v2 still listed after delete: {versions_after}"

    # The list omission and the resource's own existence must agree: an independent
    # read (DescribeStateMachine, not ListStateMachineVersions) on the deleted version
    # must report it specifically gone, not just missing from one collection.
    describe_code, describe_message = _error(lambda: sfn.describe_state_machine(stateMachineArn=v2_arn))
    assert describe_code == "StateMachineDoesNotExist", (
        f"expected StateMachineDoesNotExist from DescribeStateMachine on the deleted version, "
        f"got {describe_code!r}"
    )
    expected = f"State Machine Version Does Not Exist: '{v2_arn}'"
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"
    assert sfn.describe_state_machine(stateMachineArn=v1_arn)["stateMachineArn"] == v1_arn, (
        "v1 must remain independently describable after its sibling version was deleted"
    )
    assert sfn.describe_state_machine(stateMachineArn=v3_arn)["stateMachineArn"] == v3_arn, (
        "v3 must remain independently describable after its sibling version was deleted"
    )


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
_DEF_V3 = {
    "Comment": "v3",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "v3", "End": True}},
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


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)
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
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type
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
