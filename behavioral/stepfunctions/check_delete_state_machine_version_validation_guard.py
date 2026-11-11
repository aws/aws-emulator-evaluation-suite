"""delete-state-machine-version-validation-guard."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-state-machine-version-validation-guard"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, so the
    outcome never rests on an execution role the account happens to carry."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStateMachineVersion on the unqualified state machine ARN fails with InvalidArn and the exact
    message and leaves the state machine ACTIVE, while the same call on a published version deletes
    it (StateMachineDoesNotExist afterwards)."""
    sfn = ctx.client("stepfunctions")
    definition = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}
    arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))

    # Positive control: publish a real version and delete it through the same API.
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    listed = {
        v["stateMachineVersionArn"]
        for v in sfn.list_state_machine_versions(stateMachineArn=arn)["stateMachineVersions"]
    }
    assert v1_arn in listed, f"published version {v1_arn} missing from {listed}"

    sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn)

    # DeleteStateMachineVersion is asynchronous: the version can remain listed and
    # describable for a window before it finally reports gone. Poll both independent
    # reads together well past that window.
    def _version_gone():
        listed_now = {
            v["stateMachineVersionArn"]
            for v in sfn.list_state_machine_versions(stateMachineArn=arn)["stateMachineVersions"]
        }
        try:
            sfn.describe_state_machine(stateMachineArn=v1_arn)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return v1_arn not in listed_now, err.get("Code"), err.get("Message")
        return v1_arn not in listed_now, "<still describable>", None

    listed_clear, desc_code, desc_message = _poll_until(
        _version_gone,
        lambda r: r[0] and r[1] == "StateMachineDoesNotExist",
        timeout_s=180,
        interval_s=2.0,
        description="deleted version drops from ListStateMachineVersions and DescribeStateMachine",
    )
    assert listed_clear and desc_code == "StateMachineDoesNotExist", (
        f"deleted version {v1_arn} not fully gone: listed_clear={listed_clear}, desc_code={desc_code}"
    )
    expected = f"State Machine Version Does Not Exist: '{v1_arn}'"
    assert desc_message == expected, f"expected message {expected!r}, got {desc_message!r}"

    # DeleteStateMachineVersion is idempotent: repeating it on an already-gone version
    # is a no-op, not a StateMachineDoesNotExist error.
    sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn)

    # Negative: the base (unqualified) ARN is never itself a version, and can never become one.
    code, message = _error(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=arn))
    assert code == "InvalidArn", f"expected InvalidArn, got {code}"
    expected = f"Arn missing version qualifier: {arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    desc = sfn.describe_state_machine(stateMachineArn=arn)
    assert desc["stateMachineArn"] == arn and desc["status"] == "ACTIVE", (
        f"base state machine affected by the rejected call: {desc}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
